"""Apple developer-service account, device, and App ID calls."""

from dataclasses import dataclass
import base64
import binascii
import json
import plistlib
import unicodedata
from urllib.parse import urlencode
from uuid import uuid4

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from apple_account import AnisetteData, AppleSession, XcodeToken
from certificate import DevelopmentCertificate
from provisioning import ProvisioningProfile, RegisteredAppID, RegisteredDevice


# AltSign's developer-service protocol and client identifiers.
BASE_URL = "https://developerservices2.apple.com/services/QH65B2/"
SERVICES_BASE_URL = "https://developerservices2.apple.com/services/v1/"
CLIENT_ID = "XABBG36SBA"
PROTOCOL_VERSION = "QH65B2"


@dataclass
class DeveloperTeam:
    name: str
    identifier: str


@dataclass
class DeveloperAccount:
    name: str
    teams: list[DeveloperTeam]


def _request_action(
    http: requests.Session,
    action: str,
    session: AppleSession,
    token: XcodeToken,
    anisette: AnisetteData,
    parameters: dict = None,
) -> dict:
    if not session.dsid or not token.token:
        raise ValueError("An authenticated Apple session and Xcode token are required.")

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Apple-I-Identity-Id": session.dsid,
        "X-Apple-GS-Token": token.token,
        "X-MMe-Client-Info": anisette.client_info,
        "X-Apple-I-Locale": anisette.headers["X-Apple-Locale"],
    }
    headers.update(anisette.headers)

    body = {
        "clientId": CLIENT_ID,
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": str(uuid4()).upper(),
    }
    if parameters:
        body.update(parameters)
    response = http.post(
        BASE_URL + action,
        params={"clientId": CLIENT_ID},
        headers=headers,
        data=plistlib.dumps(body),
        timeout=15,
    )
    response.raise_for_status()
    try:
        result = plistlib.loads(response.content)
    except (plistlib.InvalidFileException, TypeError, ValueError) as exc:
        raise RuntimeError(f"Apple returned an invalid {action} response.") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"Apple returned an invalid {action} response.")
    code = result.get("resultCode")
    if code is not None and str(code) != "0":
        message = result.get("userString") or result.get("resultString") or "Unknown error"
        raise RuntimeError(f"Apple developer service failed: {message} ({code}).")
    return result


def _parse_device(raw: dict) -> RegisteredDevice:
    if not isinstance(raw, dict):
        raise RuntimeError("Apple returned an invalid device.")
    identifier = raw.get("deviceNumber")
    name = raw.get("name")
    device_id = raw.get("deviceId")
    if not isinstance(identifier, str) or not identifier or not isinstance(name, str) or not name:
        raise RuntimeError("Apple returned a device without a UDID or name.")
    return RegisteredDevice(identifier, name, str(device_id) if device_id is not None else None)


def _parse_app_id(raw: dict) -> RegisteredAppID:
    if not isinstance(raw, dict):
        raise RuntimeError("Apple returned an invalid App ID.")
    bundle_identifier = raw.get("identifier")
    name = raw.get("name")
    app_id = raw.get("appIdId")
    if not isinstance(bundle_identifier, str) or not bundle_identifier:
        raise RuntimeError("Apple returned an App ID without a bundle identifier.")
    if not isinstance(name, str) or not name:
        raise RuntimeError("Apple returned an App ID without a name.")
    return RegisteredAppID(
        bundle_identifier, name, str(app_id) if app_id is not None else None
    )


def _apple_app_name(name: str, bundle_id: str) -> str:
    normalized = unicodedata.normalize("NFKD", name)
    cleaned = "".join(
        character for character in normalized
        if character.isascii() and (character.isalnum() or character.isspace())
    )
    return " ".join(cleaned.split()) or "App " + bundle_id.replace(".", " ")


def _parse_certificate(raw: dict) -> DevelopmentCertificate:
    if not isinstance(raw, dict):
        raise RuntimeError("Apple returned an invalid certificate.")
    attributes = raw.get("attributes", raw)
    if not isinstance(attributes, dict):
        raise RuntimeError("Apple returned invalid certificate attributes.")
    content = attributes.get("certContent") or attributes.get("certificateContent")
    certificate_pem = None
    if content is not None:
        if isinstance(content, str):
            try:
                content = base64.b64decode(content, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise RuntimeError("Apple returned invalid certificate data.") from exc
        if not isinstance(content, bytes):
            raise RuntimeError("Apple returned invalid certificate data.")
        try:
            certificate = (
                x509.load_pem_x509_certificate(content)
                if content.startswith(b"-----BEGIN CERTIFICATE-----")
                else x509.load_der_x509_certificate(content)
            )
        except ValueError as exc:
            raise RuntimeError("Apple returned an invalid X.509 certificate.") from exc
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        serial_number = format(certificate.serial_number, "X")
    else:
        serial_number = attributes.get("serialNumber") or attributes.get("serialNum")
        if not isinstance(serial_number, str) or not serial_number:
            raise RuntimeError("Apple returned a certificate without a serial number.")
    return DevelopmentCertificate(serial_number, certificate_pem)


class DeveloperClient:
    def __init__(
        self,
        session: AppleSession,
        token: XcodeToken,
        anisette: AnisetteData,
        http: requests.Session = None,
    ):
        self.session = session
        self.token = token
        self.anisette = anisette
        self.http = http if http is not None else requests.Session()

    def get_devices(self, team: DeveloperTeam) -> list[RegisteredDevice]:
        result = _request_action(
            self.http, "ios/listDevices.action", self.session, self.token,
            self.anisette, {"teamId": team.identifier},
        )
        raw_devices = result.get("devices")
        if not isinstance(raw_devices, list):
            raise RuntimeError("Apple did not return a device list.")
        return [_parse_device(raw) for raw in raw_devices]

    def register_device(self, team: DeveloperTeam, udid: str, name: str) -> RegisteredDevice:
        result = _request_action(
            self.http, "ios/addDevice.action", self.session, self.token,
            self.anisette,
            {"teamId": team.identifier, "deviceNumber": udid, "name": name},
        )
        if "device" not in result:
            raise RuntimeError("Apple did not confirm device registration.")
        device = _parse_device(result["device"])
        if device.identifier.upper() != udid.upper():
            raise RuntimeError("Apple returned a different device after registration.")
        return device

    def get_app_ids(self, team: DeveloperTeam) -> list[RegisteredAppID]:
        result = _request_action(
            self.http, "ios/listAppIds.action", self.session, self.token,
            self.anisette, {"teamId": team.identifier},
        )
        raw_app_ids = result.get("appIds")
        if not isinstance(raw_app_ids, list):
            raise RuntimeError("Apple did not return an App ID list.")
        return [_parse_app_id(raw) for raw in raw_app_ids]

    def register_app_id(
        self, team: DeveloperTeam, bundle_id: str, name: str
    ) -> RegisteredAppID:
        result = _request_action(
            self.http, "ios/addAppId.action", self.session, self.token,
            self.anisette,
            {
                "teamId": team.identifier,
                "identifier": bundle_id,
                "name": _apple_app_name(name, bundle_id),
            },
        )
        if "appId" not in result:
            raise RuntimeError("Apple did not confirm App ID registration.")
        app_id = _parse_app_id(result["appId"])
        if app_id.bundle_identifier.casefold() != bundle_id.casefold():
            raise RuntimeError("Apple returned a different App ID after registration.")
        return app_id

    def get_certificates(self, team: DeveloperTeam) -> list[DevelopmentCertificate]:
        query = urlencode({
            "teamId": team.identifier,
            "filter[certificateType]": "IOS_DEVELOPMENT",
        })
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "Accept-Language": "en-us",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-HTTP-Method-Override": "GET",
            "X-Apple-I-Identity-Id": self.session.dsid,
            "X-Apple-GS-Token": self.token.token,
            "X-MMe-Client-Info": self.anisette.client_info,
        }
        headers.update(self.anisette.headers)
        response = self.http.post(
            SERVICES_BASE_URL + "certificates",
            headers=headers,
            data=json.dumps({"urlEncodedQueryParams": query}),
            timeout=15,
        )
        response.raise_for_status()
        try:
            result = response.json()
        except ValueError as exc:
            raise RuntimeError("Apple returned an invalid certificate list.") from exc
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            raise RuntimeError("Apple did not return a certificate list.")
        return [_parse_certificate(raw) for raw in result["data"]]

    def create_certificate(
        self, team: DeveloperTeam, csr: x509.CertificateSigningRequest,
        machine_name: str,
    ) -> DevelopmentCertificate:
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
        result = _request_action(
            self.http, "ios/submitDevelopmentCSR.action", self.session,
            self.token, self.anisette,
            {
                "teamId": team.identifier,
                "csrContent": csr_pem,
                "machineId": str(uuid4()).upper(),
                "machineName": machine_name,
            },
        )
        certificate_data = result.get("certRequest")
        if not isinstance(certificate_data, dict):
            raise RuntimeError("Apple did not return a development certificate.")
        certificate = _parse_certificate(certificate_data)
        if certificate.certificate_pem is None:
            raise RuntimeError("Apple returned a certificate record without certificate data.")
        return certificate

    def download_team_provisioning_profile(
        self, team: DeveloperTeam, app_id: RegisteredAppID
    ) -> ProvisioningProfile:
        if not app_id.app_id:
            raise ValueError("The App ID is missing Apple's internal identifier.")
        result = _request_action(
            self.http, "ios/downloadTeamProvisioningProfile.action",
            self.session, self.token, self.anisette,
            {"teamId": team.identifier, "appIdId": app_id.app_id},
        )
        raw = result.get("provisioningProfile")
        if not isinstance(raw, dict):
            raise RuntimeError("Apple did not return a provisioning profile.")
        data = raw.get("encodedProfile")
        if not isinstance(data, bytes) or not data:
            raise RuntimeError("Apple returned a provisioning profile without CMS data.")
        return ProvisioningProfile(
            name=str(raw.get("name") or ""),
            identifier=str(raw.get("provisioningProfileId") or ""),
            data=data,
        )


def get_developer_account(
    session: AppleSession,
    token: XcodeToken,
    anisette: AnisetteData,
    http: requests.Session = None,
) -> DeveloperAccount:
    own_http = http is None
    http = http or requests.Session()
    try:
        developer_response = _request_action(
            http, "viewDeveloper.action", session, token, anisette
        )
        developer = developer_response.get("developer")
        if not isinstance(developer, dict):
            raise RuntimeError("Apple did not return a developer account.")
        name = developer.get("name") or " ".join(
            part for part in (developer.get("firstName"), developer.get("lastName"))
            if isinstance(part, str) and part.strip()
        )
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError("Apple did not return a developer name.")

        teams_response = _request_action(
            http, "listTeams.action", session, token, anisette
        )
        raw_teams = teams_response.get("teams")
        if not isinstance(raw_teams, list):
            raise RuntimeError("Apple did not return a team list.")
        teams = []
        for team in raw_teams:
            if not isinstance(team, dict):
                raise RuntimeError("Apple returned an invalid team.")
            team_name = team.get("name")
            team_id = team.get("teamId")
            if not isinstance(team_name, str) or not team_name or not isinstance(team_id, str) or not team_id:
                raise RuntimeError("Apple returned a team without a name or ID.")
            teams.append(DeveloperTeam(team_name, team_id))
        return DeveloperAccount(name.strip(), teams)
    finally:
        if own_http:
            http.close()


def format_developer_account(account: DeveloperAccount) -> str:
    lines = ["Developer Account", "-----------------", f"Name: {account.name}", "", "Teams:"]
    for index, team in enumerate(account.teams):
        lines.extend((f"[{index}] {team.name}", f"    ID: {team.identifier}"))
    if not account.teams:
        lines.append("(none)")
    return "\n".join(lines)

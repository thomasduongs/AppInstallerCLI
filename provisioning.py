"""Device, App ID, and development provisioning-profile workflows."""

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes


PROFILE_ROOT = Path.home() / ".freshapplctl" / "profiles"


@dataclass
class RegisteredDevice:
    identifier: str
    name: str
    device_id: Optional[str] = None


@dataclass
class RegisteredAppID:
    bundle_identifier: str
    name: str
    app_id: Optional[str] = None


@dataclass
class ProvisioningProfile:
    name: str
    identifier: str
    data: bytes


def _profile_path(team_id, bundle_id, root):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", team_id):
        raise ValueError("Invalid developer team ID.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", bundle_id):
        raise ValueError("Invalid bundle identifier for a profile filename.")
    return Path(root) / team_id / f"{bundle_id}.mobileprovision"


def inspect_profile(data):
    """Decode the CMS-wrapped plist using macOS's security tool."""
    if not isinstance(data, bytes) or not data:
        raise RuntimeError("Provisioning profile has no CMS data.")
    with tempfile.NamedTemporaryFile(suffix=".mobileprovision") as source:
        source.write(data)
        source.flush()
        result = subprocess.run(
            ["security", "cms", "-D", "-i", source.name],
            capture_output=True, timeout=15, check=False,
        )
    if result.returncode != 0:
        raise RuntimeError("Could not decode the provisioning profile CMS container.")
    try:
        details = plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, TypeError, ValueError) as exc:
        raise RuntimeError("Provisioning profile contains an invalid plist.") from exc
    if not isinstance(details, dict):
        raise RuntimeError("Provisioning profile contains an invalid plist.")
    return details


def validate_profile(profile, team_id, bundle_id, udid, certificate_pem):
    details = inspect_profile(profile.data)
    teams = details.get("TeamIdentifier")
    if not isinstance(teams, list) or team_id not in teams:
        raise RuntimeError("Provisioning profile belongs to a different team.")
    devices = details.get("ProvisionedDevices")
    if not isinstance(devices, list) or udid.upper() not in {
        value.upper() for value in devices if isinstance(value, str)
    }:
        raise RuntimeError("Provisioning profile does not include the selected device.")
    entitlements = details.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise RuntimeError("Provisioning profile has no entitlements.")
    app_identifier = entitlements.get("application-identifier")
    if not isinstance(app_identifier, str) or not app_identifier.endswith("." + bundle_id):
        raise RuntimeError("Provisioning profile does not match the IPA bundle ID.")
    prefix = app_identifier[:-(len(bundle_id) + 1)]
    prefixes = details.get("ApplicationIdentifierPrefix")
    if not isinstance(prefixes, list) or prefix not in prefixes:
        raise RuntimeError("Provisioning profile has an unexpected App ID prefix.")
    entitlement_team = entitlements.get("com.apple.developer.team-identifier")
    if entitlement_team is not None and entitlement_team != team_id:
        raise RuntimeError("Provisioning profile entitlements name a different team.")
    if entitlements.get("get-task-allow") is not True:
        raise RuntimeError("Provisioning profile is not an iOS development profile.")
    expiry = details.get("ExpirationDate")
    if not isinstance(expiry, datetime):
        raise RuntimeError("Provisioning profile has no expiration date.")
    expiry_utc = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry.astimezone(timezone.utc)
    if expiry_utc <= datetime.now(timezone.utc):
        raise RuntimeError("Provisioning profile has expired.")
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise RuntimeError("Local development certificate is invalid.") from exc
    certificate_fingerprint = certificate.fingerprint(hashes.SHA256())
    raw_certificates = details.get("DeveloperCertificates")
    if not isinstance(raw_certificates, list):
        raise RuntimeError("Provisioning profile has no development certificates.")
    fingerprints = set()
    for raw in raw_certificates:
        if isinstance(raw, bytes):
            try:
                fingerprints.add(
                    x509.load_der_x509_certificate(raw).fingerprint(hashes.SHA256())
                )
            except ValueError:
                continue
    if certificate_fingerprint not in fingerprints:
        raise RuntimeError("Provisioning profile does not include the local certificate.")
    name = details.get("Name")
    identifier = details.get("UUID")
    if not isinstance(name, str) or not isinstance(identifier, str):
        raise RuntimeError("Provisioning profile is missing its name or UUID.")
    return ProvisioningProfile(name, identifier, profile.data)


def save_profile(profile, bundle_id, team_id, root=PROFILE_ROOT):
    path = _profile_path(team_id, bundle_id, root)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
        raise RuntimeError("Provisioning profile directory is not private.")
    if path.is_symlink():
        raise RuntimeError("Refusing to overwrite a provisioning profile symlink.")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".profile-", delete=False) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            output.write(profile.data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return path


class ProvisioningManager:
    def __init__(self, developer_client, team):
        self.developer = developer_client
        self.team = team

    def get_devices(self):
        return self.developer.get_devices(self.team)

    def find_device(self, udid):
        for device in self.get_devices():
            if device.identifier.upper() == udid.upper():
                return device
        return None

    def register_device(self, udid, name):
        if not udid or not udid.strip():
            raise ValueError("A device UDID is required.")
        if not name or not name.strip():
            raise ValueError("A device name is required.")

        print("Checking registration...")
        existing = self.find_device(udid)
        if existing is not None:
            print("Device already registered.")
            return existing

        print("Registering device...")
        registered = self.developer.register_device(
            team=self.team, udid=udid, name=name
        )
        print("Device registered successfully.")
        return registered

    def find_app_id(self, bundle_id):
        for app_id in self.developer.get_app_ids(self.team):
            if app_id.bundle_identifier.casefold() == bundle_id.casefold():
                return app_id
        return None

    def get_or_create_app_id(self, bundle_id, name):
        if not isinstance(bundle_id, str) or not bundle_id.strip():
            raise ValueError("A bundle identifier is required.")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("An app name is required.")

        print("Checking App ID...")
        existing = self.find_app_id(bundle_id)
        if existing is not None:
            print("App ID already exists.")
            return existing

        print("Creating App ID...")
        app_id = self.developer.register_app_id(
            team=self.team, bundle_id=bundle_id, name=name
        )
        print("App ID registered successfully.")
        return app_id

    def get_or_create_profile(
        self, app_id, certificate_path, device, bundle_id, root=PROFILE_ROOT
    ):
        path = _profile_path(self.team.identifier, bundle_id, root)
        certificate_pem = Path(certificate_path).read_bytes()
        if path.exists():
            if path.is_symlink():
                raise RuntimeError("Refusing to read a provisioning profile symlink.")
            try:
                local = validate_profile(
                    ProvisioningProfile("", "", path.read_bytes()),
                    self.team.identifier, bundle_id, device.identifier,
                    certificate_pem,
                )
            except RuntimeError:
                print("Local provisioning profile is stale; requesting a fresh one.")
            else:
                print("Using existing provisioning profile.")
                return local, path

        print("Requesting provisioning profile from Apple...")
        downloaded = self.developer.download_team_provisioning_profile(
            self.team, app_id
        )
        profile = validate_profile(
            downloaded, self.team.identifier, bundle_id, device.identifier,
            certificate_pem,
        )
        saved_path = save_profile(profile, bundle_id, self.team.identifier, root)
        print("Provisioning profile ready.")
        return profile, saved_path

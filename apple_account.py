from dataclasses import dataclass
import locale
from Foundation import NSBundle, NSClassFromString
import subprocess
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import plistlib

import requests
import srp._pysrp as srp

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

@dataclass
class AnisetteData:
    headers: dict[str, str]
    client_info: str

AOSKIT_PATH = "/System/Library/PrivateFrameworks/AOSKit.framework"

def shell(command):
    return subprocess.check_output(
        command,
        text=True
    ).strip()

def get_anisette_data() -> AnisetteData:

    
    bundle = NSBundle.bundleWithPath_(AOSKIT_PATH)

    if bundle is None:
        raise RuntimeError("AOSKit.framework not found")
    if not bundle.load():
        raise RuntimeError("could not load AOSKit.framework")

    utilities = NSClassFromString("AOSUtilities")

    if utilities is None:
        raise RuntimeError("could not find AOSUtilities")

    result = utilities.retrieveOTPHeadersForDSID_("-2")

    if result is None:
        raise RuntimeError("macOS did not return Anisette data.")

    machine_id = str(result["X-Apple-MD-M"])
    one_time_password = str(result["X-Apple-MD"])

    device_id = str(utilities.machineUDID())
    serial_number = str(utilities.machineSerialNumber())

    local_user_id = base64.b64encode(
        device_id.encode()
    ).decode()

    mac_model = shell(["sysctl", "-n", "hw.model"])
    mac_version = shell(["sw_vers", "-productVersion"])
    mac_build = shell(["sw_vers", "-buildVersion"])

    xcode_client_version = "25183.54.10"

    client_info = (
        f"<{mac_model}> "
        f"<macOS;{mac_version};{mac_build}> "
        f"<com.apple.AuthKit/1 "
        f"(com.apple.dt.Xcode/{xcode_client_version})>"
    )

    current_locale = locale.getlocale()[0] or "en_US"

    client_time = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    headers = {
        "X-Apple-I-Client-Time": client_time,
        "X-Apple-I-MD": one_time_password,
        "X-Apple-I-MD-LU": local_user_id,
        "X-Apple-I-MD-M": machine_id,
        "X-Apple-I-MD-RINFO": "84215040",
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-SRL-NO": serial_number,
        "X-Apple-I-TimeZone": str(
            datetime.now().astimezone().tzinfo
        ),
        "X-Apple-Locale": current_locale,
    }

    return AnisetteData(headers=headers)

@dataclass
class AppleSession:
    apple_id: str
    dsid: str
    idms_token: str
    payload: dict
    auth_type: str | None

srp.rfc5054_enable()
srp.no_username_in_x()

def build_cpd(anisette: AnisetteData):
    headers = anisette.headers

    return {
        "bootstrap": True,
        "icscrec": True,
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",

        "loc": headers["X-Apple-Locale"],

        "X-Apple-I-Client-Time":
            headers["X-Apple-I-Client-Time"],

        "X-Apple-Locale":
            headers["X-Apple-Locale"],

        "X-Apple-I-TimeZone":
            headers["X-Apple-I-TimeZone"],

        "X-Apple-I-MD":
            headers["X-Apple-I-MD"],

        "X-Apple-I-MD-LU":
            headers["X-Apple-I-MD-LU"],

        "X-Apple-I-MD-M":
            headers["X-Apple-I-MD-M"],

        "X-Apple-I-MD-RINFO":
            int(headers["X-Apple-I-MD-RINFO"]),

        "X-Mme-Device-Id":
            headers["X-Mme-Device-Id"],

        "X-Apple-I-SRL-NO":
            headers["X-Apple-I-SRL-NO"],
    }

GSA_URL = "https://gsa.apple.com/grandslam/GsService2"


def send_gsa_request(
    session: requests.Session,
    parameters: dict,
    anisette: AnisetteData
):
    body = {
        "Header": {
            "Version": "1.0.1"
        },
        "Request": parameters
    }

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent":
            "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": anisette.client_info,
    }

    response = session.post(
        GSA_URL,
        headers=headers,
        data=plistlib.dumps(body),
        timeout=15
    )

    response.raise_for_status()

    plist = plistlib.loads(response.content)

    result = plist["Response"]

    status = result.get("Status", {})

    error_code = status.get(
        "ec",
        result.get("ec", 0)
    )

    if error_code not in (0, None):
        message = status.get(
            "em",
            result.get("em", "Unknown Apple authentication error")
        )

        raise RuntimeError(
            f"Apple authentication failed: "
            f"{error_code}: {message}"
        )

    return result

def derive_password(
    password: str,
    salt: bytes,
    iterations: int,
    protocol: str
) -> bytes:

    if protocol not in ("s2k", "s2k_fo"):
        raise RuntimeError(
            f"Unsupported SRP protocol: {protocol}"
        )

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).digest()

    if protocol == "s2k_fo":
        password_hash = password_hash.hex().encode("ascii")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password_hash,
        salt,
        iterations,
        32
    )

def decrypt_spd(
    session_key: bytes,
    encrypted_data: bytes
) -> dict:

    aes_key = hmac.new(
        session_key,
        b"extra data key:",
        hashlib.sha256
    ).digest()

    aes_iv = hmac.new(
        session_key,
        b"extra data iv:",
        hashlib.sha256
    ).digest()[:16]

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(aes_iv)
    )

    decryptor = cipher.decryptor()

    decrypted = (
        decryptor.update(encrypted_data)
        + decryptor.finalize()
    )

    unpadder = padding.PKCS7(128).unpadder()

    decrypted = (
        unpadder.update(decrypted)
        + unpadder.finalize()
    )

    return plistlib.loads(decrypted)

def authenticate_once(
    apple_id: str,
    password: str,
    anisette: AnisetteData
) -> AppleSession:

    http = requests.Session()

    # Password is intentionally empty initially.
    # We can't derive Apple's password key until the
    # server gives us the salt + iteration count.
    user = srp.User(
        apple_id,
        b"",
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )

    _, A = user.start_authentication()

    # --------------------------
    # SRP request 1: INIT
    # --------------------------

    init_response = send_gsa_request(
        http,
        {
            "A2k": A,
            "ps": [
                "s2k",
                "s2k_fo"
            ],
            "cpd": build_cpd(anisette),
            "u": apple_id,
            "o": "init"
        },
        anisette
    )

    salt = init_response["s"]
    B = init_response["B"]
    iterations = int(init_response["i"])

    protocol = init_response.get(
        "sp",
        "s2k"
    )

    continuation = init_response["c"]

    print(
        f"Apple selected {protocol}, "
        f"{iterations} PBKDF2 rounds."
    )

    password_key = derive_password(
        password,
        salt,
        iterations,
        protocol
    )

    # Replace the empty SRP password with Apple's
    # derived password.
    user.p = password_key

    M1 = user.process_challenge(
        salt,
        B
    )

    if M1 is None:
        raise RuntimeError(
            "Could not generate SRP proof."
        )

    # --------------------------
    # SRP request 2: COMPLETE
    # --------------------------

    complete_response = send_gsa_request(
        http,
        {
            "c": continuation,
            "M1": M1,
            "cpd": build_cpd(anisette),
            "u": apple_id,
            "o": "complete"
        },
        anisette
    )

    M2 = complete_response.get("M2")

    if M2 is None:
        raise RuntimeError(
            "Apple did not return an SRP server proof."
        )

    user.verify_session(M2)

    if not user.authenticated():
        raise RuntimeError(
            "Could not verify Apple's SRP proof."
        )

    session_key = user.get_session_key()

    if session_key is None:
        raise RuntimeError(
            "SRP session key missing."
        )

    encrypted_spd = complete_response.get("spd")

    if encrypted_spd is None:
        raise RuntimeError(
            "Apple did not return session data."
        )

    payload = decrypt_spd(
        session_key,
        encrypted_spd
    )

    dsid = payload.get("adsid")
    idms_token = payload.get("GsIdmsToken")

    if not dsid or not idms_token:
        raise RuntimeError(
            "Apple session does not contain "
            "adsid/GsIdmsToken."
        )

    auth_type = (
        complete_response
        .get("Status", {})
        .get("au")
    )

    return AppleSession(
        apple_id=payload.get(
            "acname",
            apple_id
        ),
        dsid=str(dsid),
        idms_token=str(idms_token),
        payload=payload,
        auth_type=auth_type
    )

def two_factor_headers(
    apple_session: AppleSession,
    anisette: AnisetteData
):
    identity = base64.b64encode(
        (
            apple_session.dsid
            + ":"
            + apple_session.idms_token
        ).encode()
    ).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "User-Agent": "Xcode",

        "X-Apple-Identity-Token": identity,

        "X-Apple-App-Info":
            "com.apple.gs.xcode.auth",

        "X-Xcode-Version":
            "11.2 (11B41)",

        "X-MMe-Client-Info":
            anisette.client_info,
    }

    headers.update(anisette.headers)

    return headers

def request_two_factor_code(
    apple_session: AppleSession,
    anisette: AnisetteData
):
    response = requests.get(
        "https://gsa.apple.com/auth/verify/trusteddevice",
        headers=two_factor_headers(
            apple_session,
            anisette
        ),
        timeout=15
    )

    response.raise_for_status()

def submit_two_factor_code(
    apple_session: AppleSession,
    anisette: AnisetteData,
    code: str
):
    if len(code) != 6 or not code.isdigit():
        raise ValueError(
            "2FA code must contain six digits."
        )

    headers = two_factor_headers(
        apple_session,
        anisette
    )

    headers["security-code"] = code

    response = requests.get(
        "https://gsa.apple.com/"
        "grandslam/GsService2/validate",
        headers=headers,
        timeout=15
    )

    response.raise_for_status()

    if response.content:
        result = plistlib.loads(
            response.content
        )

        result = result.get(
            "Response",
            result
        )

        status = result.get(
            "Status",
            result
        )

        error = status.get("ec", 0)

        if error not in (0, None):
            raise RuntimeError(
                f"2FA failed: {error}: "
                f"{status.get('em', '')}"
            )

class AppleAccount:

    def login(
        self,
        apple_id: str,
        password: str
    ) -> AppleSession:

        print("Generating Anisette data...")

        anisette = get_anisette_data()

        print("Authenticating with Apple...")

        session = authenticate_once(
            apple_id,
            password,
            anisette
        )

        if session.auth_type is None:
            print("Authentication successful.")

            return session

        if session.auth_type == "trustedDeviceSecondaryAuth":

            print(
                "Two-factor authentication required."
            )

            request_two_factor_code(
                session,
                anisette
            )

            code = input(
                "Enter 2FA code: "
            ).strip()

            submit_two_factor_code(
                session,
                anisette,
                code
            )

            print(
                "2FA accepted. "
                "Completing authentication..."
            )

            # OTP Anisette values are short lived.
            anisette = get_anisette_data()

            final_session = authenticate_once(
                apple_id,
                password,
                anisette
            )

            if final_session.auth_type is not None:
                raise RuntimeError(
                    "Apple is still requesting "
                    f"authentication type: "
                    f"{final_session.auth_type}"
                )

            print("Authentication successful.")

            return final_session

        raise RuntimeError(
            "Unsupported secondary authentication "
            f"type: {session.auth_type}"
        )
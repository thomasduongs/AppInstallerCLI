"""Local development signing identity: encrypted key plus Apple certificate."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import secrets
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import keyring


KEYRING_SERVICE = "FreshAppleCTL Signing Identity"
IDENTITY_ROOT = Path.home() / ".freshapplctl" / "identities"


@dataclass(frozen=True)
class DevelopmentCertificate:
    serial_number: str
    certificate_pem: Optional[bytes] = field(default=None, repr=False)


def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_csr(private_key, common_name):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )


def _paths(team_id, root):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", team_id):
        raise ValueError("Invalid developer team ID.")
    folder = root / team_id
    return folder, folder / "private_key.pem", folder / "certificate.pem"


def _secure_directory(folder):
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    if folder.is_symlink() or folder.stat().st_mode & 0o077:
        raise RuntimeError(f"Signing identity directory is not private: {folder}")


def _write_private_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def _read_private_file(path):
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise RuntimeError(f"Signing identity file is not private: {path}")
    return path.read_bytes()


def _save_private_key(team_id, private_key, root):
    folder, key_path, _ = _paths(team_id, root)
    _secure_directory(folder)
    if key_path.exists():
        raise RuntimeError("A local signing key already exists; refusing to overwrite it.")
    password = secrets.token_urlsafe(48)
    encrypted_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("ascii")),
    )
    keyring.set_password(KEYRING_SERVICE, team_id, password)
    _write_private_file(key_path, encrypted_pem)


def _load_private_key(team_id, key_path):
    password = keyring.get_password(KEYRING_SERVICE, team_id)
    if not password:
        raise RuntimeError("Signing-key password is missing from macOS Keychain.")
    try:
        return serialization.load_pem_private_key(
            _read_private_file(key_path), password=password.encode("ascii")
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Could not decrypt the local signing key.") from exc


def _validate_pair(private_key, certificate_pem):
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise RuntimeError("The development certificate is invalid.") from exc
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_public != certificate_public:
        raise RuntimeError("The development certificate does not match the local private key.")
    if certificate.not_valid_after_utc <= datetime.now(timezone.utc):
        raise RuntimeError("The local development certificate has expired.")
    if certificate.not_valid_before_utc > datetime.now(timezone.utc):
        raise RuntimeError("The local development certificate is not valid yet.")
    return certificate


def save_certificate(team_id, private_key, certificate_pem, root=IDENTITY_ROOT):
    _validate_pair(private_key, certificate_pem)
    folder, key_path, certificate_path = _paths(team_id, Path(root))
    if not key_path.exists():
        raise RuntimeError("Save the encrypted private key before its certificate.")
    _secure_directory(folder)
    _write_private_file(certificate_path, certificate_pem)
    return certificate_path


def _remote_has_certificate(remote_certificates, local_certificate):
    for remote in remote_certificates:
        try:
            serial = int(remote.serial_number.replace(":", ""), 16)
        except ValueError:
            continue
        if serial == local_certificate.serial_number:
            return True
    return False


def get_or_create_certificate(developer, team, root=IDENTITY_ROOT):
    folder, key_path, certificate_path = _paths(team.identifier, Path(root))
    print("Checking development certificates...")
    remote_certificates = developer.get_certificates(team)

    if certificate_path.exists() and not key_path.exists():
        raise RuntimeError("A local certificate exists without its private key; cannot sign.")

    if key_path.exists():
        private_key = _load_private_key(team.identifier, key_path)
        if certificate_path.exists():
            certificate = _validate_pair(
                private_key, _read_private_file(certificate_path)
            )
            if not _remote_has_certificate(remote_certificates, certificate):
                raise RuntimeError("The local signing certificate is not on this developer team.")
            print("Using existing local signing identity.")
            return certificate_path

        # A previous run may have submitted the CSR but failed before saving
        # the certificate. Recover it if Apple returns the signed bytes.
        for remote in remote_certificates:
            if remote.certificate_pem is None:
                continue
            try:
                _validate_pair(private_key, remote.certificate_pem)
            except RuntimeError:
                continue
            save_certificate(team.identifier, private_key, remote.certificate_pem, root)
            print("Recovered development certificate for the local key.")
            return certificate_path
        raise RuntimeError(
            "A local signing key exists but its certificate is missing. "
            "Keep this key; resolve the prior certificate request before retrying."
        )

    print("No usable local identity found.")
    print("Generating private key...")
    private_key = generate_private_key()
    _save_private_key(team.identifier, private_key, Path(root))
    print("Creating CSR...")
    csr = create_csr(private_key, f"iOS Development: {team.name}")
    print("Requesting certificate from Apple...")
    issued = developer.create_certificate(team, csr, "FreshAppleCTL")
    if issued.certificate_pem is None:
        raise RuntimeError("Apple issued a certificate without certificate data.")
    certificate = _validate_pair(private_key, issued.certificate_pem)
    if int(issued.serial_number.replace(":", ""), 16) != certificate.serial_number:
        raise RuntimeError("Apple returned a certificate with a mismatched serial number.")
    save_certificate(team.identifier, private_key, issued.certificate_pem, root)
    print("Development certificate created.")
    return certificate_path

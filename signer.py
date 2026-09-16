"""Re-sign a simple iOS IPA with a local development identity and profile."""

from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import plistlib
import secrets
import shutil
import stat
import subprocess
import tempfile
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from certificate import _load_private_key, _read_private_file, _validate_pair
from ipa import read_ipa
from provisioning import inspect_profile, validate_profile, ProvisioningProfile


def _run(command):
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{command[0]} failed: {detail}")
    return result


@contextmanager
def _signing_keychain(private_key, certificate, folder):
    """Keep the imported identity out of the user's normal keychains."""
    keychain = folder / "signing.keychain-db"
    p12_path = folder / "identity.p12"
    password = secrets.token_urlsafe(32)
    p12_path.write_bytes(pkcs12.serialize_key_and_certificates(
        b"FreshAppleCTL", private_key, certificate, None,
        serialization.BestAvailableEncryption(password.encode()),
    ))
    os.chmod(p12_path, 0o600)
    created = False
    try:
        _run(["security", "create-keychain", "-p", password, str(keychain)])
        created = True
        _run(["security", "unlock-keychain", "-p", password, str(keychain)])
        _run(["security", "import", str(p12_path), "-k", str(keychain),
              "-P", password, "-T", "/usr/bin/codesign"])
        _run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
              "-s", "-k", password, str(keychain)])
        yield keychain
    finally:
        p12_path.unlink(missing_ok=True)
        if created:
            subprocess.run(["security", "delete-keychain", str(keychain)],
                           capture_output=True, check=False)


def _extract_ipa(source, destination):
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        if len(entries) > 100000 or sum(item.file_size for item in entries) > 8 * 1024 ** 3:
            raise ValueError("IPA is too large to extract safely.")
        seen = set()
        for item in entries:
            name = item.filename
            parts = PurePosixPath(name).parts
            mode = (item.external_attr >> 16) & 0xffff
            kind = stat.S_IFMT(mode)
            if (not name or name.startswith("/") or "\\" in name
                    or any(part in (".", "..") for part in parts)
                    or kind not in (0, stat.S_IFDIR, stat.S_IFREG)):
                raise ValueError(f"Unsafe IPA entry: {name}")
            normalized = name.rstrip("/")
            if normalized in seen or not parts:
                raise ValueError(f"Unsafe or duplicate IPA entry: {name}")
            seen.add(normalized)
            target = destination.joinpath(*parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as incoming, target.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            os.chmod(target, (mode & 0o777) or 0o644)


def _entitlements(profile_data, bundle_id):
    details = inspect_profile(profile_data)
    values = details.get("Entitlements")
    if not isinstance(values, dict):
        raise RuntimeError("Provisioning profile has no entitlements.")
    entitlements = dict(values)
    app_id = entitlements.get("application-identifier")
    if not isinstance(app_id, str) or not app_id.endswith("." + bundle_id):
        raise RuntimeError("Profile entitlements do not match the app bundle ID.")
    groups = entitlements.get("keychain-access-groups")
    if groups is not None:
        if not isinstance(groups, list) or any(not isinstance(group, str) for group in groups):
            raise RuntimeError("Invalid keychain access groups in profile.")
        entitlements["keychain-access-groups"] = [
            group[:-1] + bundle_id if group.endswith(".*") else group
            for group in groups
        ]
    return plistlib.dumps(entitlements)


def _nested_code(app):
    if list(app.rglob("*.appex")) or list(app.rglob("*.app")) or list(app.rglob("*.xpc")):
        raise RuntimeError(
            "This IPA contains an extension or nested app. Each needs its own App ID "
            "and provisioning profile; signing stopped before creating an invalid IPA."
        )
    targets = [path for path in app.rglob("*")
               if path.is_dir() and path.suffix == ".framework"]
    targets += [path for path in app.rglob("*")
                if path.is_file() and path.suffix == ".dylib"]
    return sorted(set(targets), key=lambda path: len(path.parts), reverse=True)


def _package_ipa(extracted, output):
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         allowZip64=True) as archive:
        for path in sorted(extracted.rglob("*")):
            if path.is_symlink():
                raise RuntimeError(f"Unexpected symlink in signed app: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(extracted).as_posix()
            archive.write(path, relative)


def sign_ipa(ipa_path, profile_path, certificate_path, team_id, udid,
             output_path=None):
    """Return the signed IPA path; leave the original IPA untouched."""
    source = Path(ipa_path).resolve(strict=True)
    metadata = read_ipa(source)
    certificate_path = Path(certificate_path)
    certificate_pem = _read_private_file(certificate_path)
    private_key = _load_private_key(team_id, certificate_path.with_name("private_key.pem"))
    certificate = _validate_pair(private_key, certificate_pem)
    profile_data = Path(profile_path).read_bytes()
    validate_profile(ProvisioningProfile("", "", profile_data), team_id,
                     metadata.bundle_identifier, udid, certificate_pem)
    output = Path(output_path) if output_path else source.with_name(source.stem + "-signed.ipa")
    output = output.resolve()
    if output == source:
        raise ValueError("Signed output must not overwrite the input IPA.")
    if output.suffix.lower() != ".ipa":
        raise ValueError("Signed output must have an .ipa extension.")
    if output.exists():
        raise FileExistsError(f"Signed output already exists: {output}")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {output.parent}")

    with tempfile.TemporaryDirectory(prefix="freshapplctl-sign-") as temporary:
        root = Path(temporary)
        extracted = root / "extracted"
        extracted.mkdir()
        _extract_ipa(source, extracted)
        apps = list((extracted / "Payload").glob("*.app"))
        if len(apps) != 1:
            raise ValueError("IPA must contain exactly one main app.")
        app = apps[0]
        nested = _nested_code(app)
        (app / "embedded.mobileprovision").write_bytes(profile_data)
        entitlements_path = root / "entitlements.plist"
        entitlements_path.write_bytes(_entitlements(profile_data, metadata.bundle_identifier))
        identity = certificate.fingerprint(hashes.SHA1()).hex().upper()
        with _signing_keychain(private_key, certificate, root) as keychain:
            for target in nested:
                _run(["codesign", "--force", "--sign", identity, "--keychain",
                      str(keychain), str(target)])
            _run(["codesign", "--force", "--sign", identity, "--keychain",
                  str(keychain), "--entitlements", str(entitlements_path),
                  "--generate-entitlement-der", str(app)])
            _run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
        staging = root / "signed.ipa"
        _package_ipa(extracted, staging)
        with zipfile.ZipFile(staging) as archive:
            if archive.testzip() is not None:
                raise RuntimeError("Signed IPA failed ZIP integrity check.")
        shutil.move(str(staging), str(output))
    return output

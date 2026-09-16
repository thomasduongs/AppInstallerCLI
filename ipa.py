"""Read metadata from the main app inside an IPA without extracting files."""

from dataclasses import dataclass
from pathlib import Path
import plistlib
import zipfile


MAX_INFO_PLIST_SIZE = 2 * 1024 * 1024


@dataclass(frozen=True)
class IPAInfo:
    bundle_identifier: str
    display_name: str
    executable: str
    short_version: str


def read_ipa(path) -> IPAInfo:
    ipa_path = Path(path)
    if not ipa_path.is_file() or ipa_path.suffix.lower() != ".ipa":
        raise ValueError(f"Not an IPA file: {ipa_path}")

    try:
        with zipfile.ZipFile(ipa_path) as archive:
            candidates = [
                entry for entry in archive.infolist()
                if len(entry.filename.split("/")) == 3
                and entry.filename.startswith("Payload/")
                and entry.filename.split("/")[1].endswith(".app")
                and entry.filename.endswith("/Info.plist")
            ]
            if len(candidates) != 1:
                raise ValueError("IPA must contain exactly one Payload/*.app/Info.plist.")
            entry = candidates[0]
            if entry.file_size > MAX_INFO_PLIST_SIZE:
                raise ValueError("IPA Info.plist is unexpectedly large.")
            with archive.open(entry) as source:
                data = source.read(MAX_INFO_PLIST_SIZE + 1)
            if len(data) > MAX_INFO_PLIST_SIZE:
                raise ValueError("IPA Info.plist is unexpectedly large.")
    except zipfile.BadZipFile as exc:
        raise ValueError("IPA is not a valid ZIP archive.") from exc

    try:
        info = plistlib.loads(data)
    except (plistlib.InvalidFileException, TypeError, ValueError) as exc:
        raise ValueError("IPA contains an invalid Info.plist.") from exc
    if not isinstance(info, dict):
        raise ValueError("IPA contains an invalid Info.plist.")

    def required(key):
        value = info.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"IPA Info.plist is missing {key}.")
        return value.strip()

    bundle_identifier = required("CFBundleIdentifier")
    executable = required("CFBundleExecutable")
    short_version = required("CFBundleShortVersionString")
    display_name = (
        info.get("CFBundleDisplayName")
        or info.get("CFBundleName")
        or executable
    )
    if not isinstance(display_name, str) or not display_name.strip():
        display_name = executable
    return IPAInfo(bundle_identifier, display_name.strip(), executable, short_version)

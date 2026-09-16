import plistlib
import stat
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from signer import _entitlements, _extract_ipa, _nested_code, sign_ipa


class SignerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_entitlements_expand_keychain_wildcard(self):
        details = {"Entitlements": {
            "application-identifier": "TEAM.com.example.app",
            "get-task-allow": True,
            "keychain-access-groups": ["TEAM.*", "TEAM.shared"],
        }}
        with patch("signer.inspect_profile", return_value=details):
            values = plistlib.loads(_entitlements(b"profile", "com.example.app"))
        self.assertEqual(values["keychain-access-groups"],
                         ["TEAM.com.example.app", "TEAM.shared"])

    def test_extract_rejects_traversal_and_symlinks(self):
        for name, mode in [("../escape", stat.S_IFREG),
                           ("Payload/App.app/link", stat.S_IFLNK)]:
            source = self.root / "bad.ipa"
            with zipfile.ZipFile(source, "w") as archive:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (mode | 0o777) << 16
                archive.writestr(info, b"content")
            with self.assertRaises(ValueError):
                _extract_ipa(source, self.root / "extract")

    def test_extension_requires_its_own_profile(self):
        app = self.root / "Payload" / "App.app"
        (app / "PlugIns" / "Widget.appex").mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, "own App ID"):
            _nested_code(app)

    def test_sign_rejects_output_overwriting_source(self):
        source = self.root / "App.ipa"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": "com.example.app",
                "CFBundleExecutable": "App",
                "CFBundleShortVersionString": "1.0",
            }))
        with patch("signer._read_private_file", return_value=b"cert"), \
             patch("signer._load_private_key"), \
             patch("signer._validate_pair"), \
             patch("signer.validate_profile"):
            profile = self.root / "profile.mobileprovision"
            profile.write_bytes(b"profile")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                sign_ipa(source, profile, self.root / "certificate.pem",
                         "TEAM", "UDID", source)

    def test_sign_embeds_profile_and_signs_nested_code_first(self):
        source = self.root / "App.ipa"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": "com.example.app",
                "CFBundleExecutable": "App",
                "CFBundleShortVersionString": "1.0",
            }))
            archive.writestr("Payload/App.app/App", b"executable")
            archive.writestr("Payload/App.app/Frameworks/Lib.framework/Lib", b"library")
        profile = self.root / "profile.mobileprovision"
        profile.write_bytes(b"profile")
        output = self.root / "signed.ipa"
        commands = []

        @contextmanager
        def fake_keychain(key, cert, folder):
            yield folder / "keychain"

        with patch("signer._read_private_file", return_value=b"cert"), \
             patch("signer._load_private_key"), \
             patch("signer._validate_pair") as validate_pair, \
             patch("signer.validate_profile"), \
             patch("signer._entitlements", return_value=plistlib.dumps({})), \
             patch("signer._signing_keychain", side_effect=fake_keychain), \
             patch("signer._run", side_effect=lambda cmd: commands.append(cmd)):
            validate_pair.return_value.fingerprint.return_value = b"\x12" * 20
            result = sign_ipa(source, profile, self.root / "certificate.pem",
                              "TEAM", "UDID", output)

        self.assertEqual(result, output.resolve())
        self.assertEqual(source.exists(), True)
        with zipfile.ZipFile(result) as archive:
            self.assertEqual(archive.read("Payload/App.app/embedded.mobileprovision"), b"profile")
        signing = [cmd for cmd in commands if cmd[:2] == ["codesign", "--force"]]
        self.assertEqual(len(signing), 2)
        self.assertTrue(signing[0][-1].endswith("Lib.framework"))
        self.assertTrue(signing[1][-1].endswith("App.app"))
        self.assertIn("--generate-entitlement-der", signing[1])
        self.assertIn("--verify", commands[-1])


if __name__ == "__main__":
    unittest.main()

import io
import plistlib
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ipa import read_ipa
from main import main


class IPAReadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "MyApp.ipa"

    def write_ipa(self, info, extra=None):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Payload/MyApp.app/Info.plist", plistlib.dumps(info))
            for name, contents in (extra or {}).items():
                archive.writestr(name, contents)

    def test_reads_main_app_and_ignores_extension(self):
        self.write_ipa({
            "CFBundleIdentifier": "com.example.myapp",
            "CFBundleDisplayName": "My App",
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.2.3",
        }, {
            "Payload/MyApp.app/PlugIns/Share.appex/Info.plist": plistlib.dumps({
                "CFBundleIdentifier": "com.example.myapp.share"
            })
        })

        metadata = read_ipa(self.path)

        self.assertEqual(metadata.bundle_identifier, "com.example.myapp")
        self.assertEqual(metadata.display_name, "My App")
        self.assertEqual(metadata.executable, "MyApp")
        self.assertEqual(metadata.short_version, "1.2.3")

    def test_display_name_falls_back_to_bundle_name(self):
        self.write_ipa({
            "CFBundleIdentifier": "com.example.myapp",
            "CFBundleName": "Fallback App",
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.0",
        })
        self.assertEqual(read_ipa(self.path).display_name, "Fallback App")

    def test_missing_bundle_id_is_rejected(self):
        self.write_ipa({
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.0",
        })
        with self.assertRaisesRegex(ValueError, "CFBundleIdentifier"):
            read_ipa(self.path)

    def test_multiple_main_apps_are_rejected(self):
        self.write_ipa({
            "CFBundleIdentifier": "com.example.myapp",
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.0",
        }, {"Payload/Other.app/Info.plist": b"other"})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            read_ipa(self.path)

    def test_register_app_cli_uses_ipa_bundle_id(self):
        self.write_ipa({
            "CFBundleIdentifier": "com.example.myapp",
            "CFBundleDisplayName": "My App",
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.0",
        })
        team = SimpleNamespace(identifier="ABC123XYZ", name="Personal Team")
        account = Mock(teams=[team])
        auth_session = Mock()
        token = Mock()
        anisette = Mock()
        with patch("sys.argv", ["main.py", "register-app", str(self.path)]), \
             patch("main.load_credentials", return_value=("test@example.invalid", "secret")), \
             patch("main.save_credentials"), \
             patch("main.AppleAccount") as apple_account, \
             patch("main.get_anisette_data", return_value=anisette), \
             patch("main.get_xcode_token", return_value=token), \
             patch("main.get_developer_account", return_value=account), \
             patch("main.DeveloperClient"), \
             patch("main.ProvisioningManager") as manager:
            apple_account.return_value.login.return_value = auth_session
            with redirect_stdout(io.StringIO()):
                main()

        manager.return_value.get_or_create_app_id.assert_called_once_with(
            "com.example.myapp", "My App"
        )

    def test_provision_cli_wires_all_inputs(self):
        self.write_ipa({
            "CFBundleIdentifier": "com.example.myapp",
            "CFBundleDisplayName": "My App",
            "CFBundleExecutable": "MyApp",
            "CFBundleShortVersionString": "1.0",
        })
        team = SimpleNamespace(identifier="ABC123XYZ", name="Personal Team")
        device = SimpleNamespace(serial="00008120-ABC")
        account = SimpleNamespace(teams=[team])
        with patch("sys.argv", ["main.py", "provision", str(self.path)]), \
             patch("main.get_devices", new=lambda: object()), \
             patch("main.asyncio.run", return_value=[device]), \
             patch("main.load_credentials", return_value=("test@example.invalid", "secret")), \
             patch("main.save_credentials"), \
             patch("main.AppleAccount"), \
             patch("main.get_anisette_data"), \
             patch("main.get_xcode_token"), \
             patch("main.get_developer_account", return_value=account), \
             patch("main.DeveloperClient"), \
             patch("main.get_or_create_certificate", return_value=Path("certificate.pem")), \
             patch("main.ProvisioningManager") as manager:
            manager.return_value.get_or_create_profile.return_value = (
                Mock(), Path("profile.mobileprovision")
            )
            with redirect_stdout(io.StringIO()):
                main()

        manager.return_value.get_or_create_app_id.assert_called_once_with(
            "com.example.myapp", "My App"
        )
        manager.return_value.register_device.assert_called_once_with(
            "00008120-ABC", "FreshAppleCTL iPhone"
        )
        manager.return_value.get_or_create_profile.assert_called_once_with(
            manager.return_value.get_or_create_app_id.return_value,
            Path("certificate.pem"),
            manager.return_value.register_device.return_value,
            "com.example.myapp",
        )


if __name__ == "__main__":
    unittest.main()

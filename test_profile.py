import io
import plistlib
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from certificate import generate_private_key
from developer import DeveloperTeam
from provisioning import (
    ProvisioningManager, ProvisioningProfile, RegisteredAppID,
    RegisteredDevice, inspect_profile, validate_profile,
)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "profiles"
        self.cert_path = Path(directory.name) / "certificate.pem"
        self.team = DeveloperTeam("Personal Team", "ABC123XYZ")
        self.app_id = RegisteredAppID("com.example.myapp", "My App", "APP123")
        self.device = RegisteredDevice("00008120-ABC", "iPhone")
        self.key = generate_private_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
        now = datetime.now(timezone.utc)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(0x1234)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(self.key, hashes.SHA256())
        )
        self.cert_path.write_bytes(
            self.certificate.public_bytes(serialization.Encoding.PEM)
        )
        self.decoded_profiles = {}
        decoder_patch = patch(
            "provisioning.inspect_profile",
            side_effect=lambda data: self.decoded_profiles[data],
        )
        decoder_patch.start()
        self.addCleanup(decoder_patch.stop)

    def profile(self, *, devices=None, app_identifier=None, certificates=None):
        payload = {
            "Name": "FreshAppleCTL com.example.myapp",
            "UUID": "00000000-0000-0000-0000-000000000001",
            "TeamIdentifier": [self.team.identifier],
            "ApplicationIdentifierPrefix": [self.team.identifier],
            "ExpirationDate": datetime.now(timezone.utc) + timedelta(days=7),
            "ProvisionedDevices": devices if devices is not None else [self.device.identifier],
            "DeveloperCertificates": certificates if certificates is not None else [
                self.certificate.public_bytes(serialization.Encoding.DER)
            ],
            "Entitlements": {
                "application-identifier": app_identifier or "ABC123XYZ.com.example.myapp",
                "com.apple.developer.team-identifier": self.team.identifier,
                "get-task-allow": True,
            },
        }
        cms = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(plistlib.dumps(payload))
            .add_signer(self.certificate, self.key, hashes.SHA256())
            .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )
        self.decoded_profiles[cms] = payload
        return ProvisioningProfile(payload["Name"], payload["UUID"], cms)

    def test_cms_is_decoded_and_validated(self):
        profile = self.profile()
        decoded = plistlib.dumps(self.decoded_profiles[profile.data])
        with patch("provisioning.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = decoded
            self.assertEqual(inspect_profile(profile.data)["UUID"], profile.identifier)
            self.assertEqual(run.call_args.args[0][:3], ["security", "cms", "-D"])
        checked = validate_profile(
            profile, self.team.identifier, self.app_id.bundle_identifier,
            self.device.identifier, self.cert_path.read_bytes(),
        )
        self.assertEqual(checked.name, profile.name)

    def test_wrong_device_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "selected device"):
            validate_profile(
                self.profile(devices=["OTHER"]), self.team.identifier,
                self.app_id.bundle_identifier, self.device.identifier,
                self.cert_path.read_bytes(),
            )

    def test_wrong_certificate_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "local certificate"):
            validate_profile(
                self.profile(certificates=[]), self.team.identifier,
                self.app_id.bundle_identifier, self.device.identifier,
                self.cert_path.read_bytes(),
            )

    def test_wrong_bundle_id_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "IPA bundle ID"):
            validate_profile(
                self.profile(app_identifier="ABC123XYZ.com.example.other"),
                self.team.identifier, self.app_id.bundle_identifier,
                self.device.identifier, self.cert_path.read_bytes(),
            )

    def test_download_then_reuse_profile(self):
        developer = Mock()
        downloaded = self.profile()
        developer.download_team_provisioning_profile.return_value = downloaded
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()):
            first, path = manager.get_or_create_profile(
                self.app_id, self.cert_path, self.device,
                self.app_id.bundle_identifier, self.root,
            )
            second, reused_path = manager.get_or_create_profile(
                self.app_id, self.cert_path, self.device,
                self.app_id.bundle_identifier, self.root,
            )

        self.assertEqual(first.identifier, downloaded.identifier)
        self.assertEqual(second.identifier, downloaded.identifier)
        self.assertEqual(reused_path, path)
        self.assertEqual(path.read_bytes(), downloaded.data)
        self.assertEqual(path.stat().st_mode & 0o077, 0)
        developer.download_team_provisioning_profile.assert_called_once_with(
            self.team, self.app_id
        )

    def test_invalid_download_is_not_saved(self):
        developer = Mock()
        developer.download_team_provisioning_profile.return_value = self.profile(devices=["OTHER"])
        manager = ProvisioningManager(developer, self.team)
        with redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "selected device"):
                manager.get_or_create_profile(
                    self.app_id, self.cert_path, self.device,
                    self.app_id.bundle_identifier, self.root,
                )
        self.assertFalse((self.root / self.team.identifier).exists())

    def test_stale_local_profile_is_replaced_only_after_validation(self):
        stale = self.profile(devices=["OTHER"])
        fresh = self.profile()
        path = self.root / self.team.identifier / "com.example.myapp.mobileprovision"
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(stale.data)
        developer = Mock()
        developer.download_team_provisioning_profile.return_value = fresh
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()) as output:
            _, saved = manager.get_or_create_profile(
                self.app_id, self.cert_path, self.device,
                self.app_id.bundle_identifier, self.root,
            )

        self.assertEqual(saved, path)
        self.assertEqual(path.read_bytes(), fresh.data)
        self.assertIn("stale", output.getvalue())


if __name__ == "__main__":
    unittest.main()

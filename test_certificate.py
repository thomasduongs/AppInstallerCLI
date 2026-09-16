import base64
import io
import json
import os
import plistlib
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from apple_account import AnisetteData, AppleSession, XcodeToken
from certificate import (
    DevelopmentCertificate,
    create_csr,
    generate_private_key,
    get_or_create_certificate,
)
from developer import DeveloperClient, DeveloperTeam
from main import main


class CertificateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "identities"
        self.team = DeveloperTeam("Personal Team", "ABC123XYZ")
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
        self.certificate_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        self.issued = DevelopmentCertificate("1234", self.certificate_pem)
        passwords = {}
        set_patch = patch(
            "certificate.keyring.set_password",
            side_effect=lambda service, account, password: passwords.__setitem__(account, password),
        )
        get_patch = patch(
            "certificate.keyring.get_password",
            side_effect=lambda service, account: passwords.get(account),
        )
        set_patch.start()
        get_patch.start()
        self.addCleanup(set_patch.stop)
        self.addCleanup(get_patch.stop)

    def test_csr_contains_public_key_not_private_key(self):
        csr = create_csr(self.key, "iOS Development: Test")
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        self.assertIn(b"BEGIN CERTIFICATE REQUEST", csr_pem)
        self.assertNotIn(b"PRIVATE KEY", csr_pem)
        self.assertEqual(
            csr.public_key().public_numbers(), self.key.public_key().public_numbers()
        )

    def test_create_then_reuse_encrypted_identity(self):
        developer = Mock()
        developer.get_certificates.side_effect = [[], [DevelopmentCertificate("1234")]]
        developer.create_certificate.return_value = self.issued

        with patch("certificate.generate_private_key", return_value=self.key):
            with redirect_stdout(io.StringIO()):
                path = get_or_create_certificate(developer, self.team, self.root)
        with redirect_stdout(io.StringIO()):
            reused = get_or_create_certificate(developer, self.team, self.root)

        self.assertEqual(path, reused)
        self.assertEqual(path.read_bytes(), self.certificate_pem)
        key_path = path.with_name("private_key.pem")
        self.assertIn(b"ENCRYPTED PRIVATE KEY", key_path.read_bytes())
        self.assertNotIn(b"BEGIN RSA PRIVATE KEY", key_path.read_bytes())
        self.assertEqual(os.stat(key_path).st_mode & 0o077, 0)
        self.assertEqual(os.stat(path.parent).st_mode & 0o077, 0)
        developer.create_certificate.assert_called_once()
        submitted_csr = developer.create_certificate.call_args.args[1]
        self.assertEqual(submitted_csr.public_key().public_numbers(), self.key.public_key().public_numbers())

    def test_failed_issue_does_not_generate_second_key(self):
        developer = Mock()
        developer.get_certificates.return_value = []
        developer.create_certificate.side_effect = RuntimeError("Apple unavailable")
        with patch("certificate.generate_private_key", return_value=self.key) as generate:
            with redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "Apple unavailable"):
                    get_or_create_certificate(developer, self.team, self.root)
                with self.assertRaisesRegex(RuntimeError, "certificate is missing"):
                    get_or_create_certificate(developer, self.team, self.root)
        generate.assert_called_once()
        developer.create_certificate.assert_called_once()

    def test_developer_client_submits_only_pem_csr(self):
        session = AppleSession(
            apple_id="test@example.invalid", dsid="123456", idms_token="secret",
            payload={}, auth_type=None, session_key=b"key", continuation=b"c",
        )
        token = XcodeToken("xcode-secret", 1790000000000)
        anisette = AnisetteData(headers={"X-Apple-Locale": "en_US"}, client_info="client")
        http = Mock()
        list_response = Mock()
        list_response.json.return_value = {"data": [{"attributes": {
            "serialNumber": "1234", "name": "Test",
        }}]}
        issue_response = Mock()
        issue_response.content = plistlib.dumps({
            "resultCode": 0,
            "certRequest": {"certContent": self.certificate.public_bytes(serialization.Encoding.DER)},
        })
        http.post.side_effect = [list_response, issue_response]
        developer = DeveloperClient(session, token, anisette, http)

        listed = developer.get_certificates(self.team)
        issued = developer.create_certificate(self.team, create_csr(self.key, "Test"), "FreshAppleCTL")

        self.assertEqual(listed[0].serial_number, "1234")
        self.assertEqual(issued.certificate_pem, self.certificate_pem)
        list_call, issue_call = http.post.call_args_list
        self.assertTrue(list_call.args[0].endswith("/services/v1/certificates"))
        self.assertEqual(list_call.kwargs["headers"]["X-HTTP-Method-Override"], "GET")
        query = json.loads(list_call.kwargs["data"])["urlEncodedQueryParams"]
        self.assertIn("filter%5BcertificateType%5D=IOS_DEVELOPMENT", query)
        self.assertTrue(issue_call.args[0].endswith("/ios/submitDevelopmentCSR.action"))
        body = plistlib.loads(issue_call.kwargs["data"])
        self.assertEqual(body["teamId"], self.team.identifier)
        self.assertIn("BEGIN CERTIFICATE REQUEST", body["csrContent"])
        self.assertNotIn("PRIVATE KEY", body["csrContent"])

    def test_certificate_cli_selects_team_and_identity_workflow(self):
        account = SimpleNamespace(teams=[self.team])
        with patch("sys.argv", ["main.py", "certificate"]), \
             patch("main.load_credentials", return_value=("test@example.invalid", "secret")), \
             patch("main.save_credentials"), \
             patch("main.AppleAccount") as apple_account, \
             patch("main.get_anisette_data"), \
             patch("main.get_xcode_token"), \
             patch("main.get_developer_account", return_value=account), \
             patch("main.DeveloperClient") as developer, \
             patch("main.get_or_create_certificate") as workflow:
            with redirect_stdout(io.StringIO()):
                main()
        self.assertIs(workflow.call_args.args[0], developer.return_value)
        self.assertIs(workflow.call_args.args[1], self.team)


if __name__ == "__main__":
    unittest.main()

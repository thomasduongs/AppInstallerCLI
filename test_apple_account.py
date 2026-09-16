import hashlib
import hmac
import plistlib
import unittest
from unittest.mock import Mock, patch

import requests

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apple_account import (
    AnisetteData,
    AppleSession,
    XCODE_AUTH_APP,
    apple_http_session,
    create_app_token_checksum,
    decrypt_app_token,
    get_xcode_token,
    send_gsa_request,
)


class XcodeTokenTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.session = AppleSession(
            apple_id="test@example.invalid",
            dsid="123456",
            idms_token="synthetic-idms-token",
            payload={},
            auth_type=None,
            session_key=self.key,
            continuation=b"synthetic-continuation",
        )
        self.anisette = AnisetteData(
            headers={
                "X-Apple-Locale": "en_US",
                "X-Apple-I-Client-Time": "2026-09-16T00:00:00Z",
                "X-Apple-I-TimeZone": "UTC",
                "X-Apple-I-MD": "synthetic-otp",
                "X-Apple-I-MD-LU": "synthetic-user",
                "X-Apple-I-MD-M": "synthetic-machine",
                "X-Apple-I-MD-RINFO": "84215040",
                "X-Mme-Device-Id": "synthetic-device",
                "X-Apple-I-SRL-NO": "synthetic-serial",
            },
            client_info="synthetic-client",
        )

    def encrypted_token(self, bare=False):
        plaintext = plistlib.dumps({
            "t": {
                XCODE_AUTH_APP: {
                    "token": "synthetic-xcode-token",
                    "expiry": 1790000000000,
                }
            }
        })
        if bare:
            plaintext = plaintext[
                plaintext.index(b"<dict>"):plaintext.rindex(b"</dict>") + 7
            ]
        iv = bytes(range(16))
        return b"XYZ" + iv + AESGCM(self.key).encrypt(iv, plaintext, b"XYZ")

    def test_checksum_uses_payload_sk_and_app_identifier(self):
        expected = hmac.new(
            self.key,
            b"apptokens123456com.apple.gs.xcode.auth",
            hashlib.sha256,
        ).digest()
        self.assertEqual(
            create_app_token_checksum(self.key, "123456", [XCODE_AUTH_APP]),
            expected,
        )

    def test_get_xcode_token_builds_request_and_decrypts_response(self):
        encrypted = self.encrypted_token()
        with patch("apple_account.send_gsa_request", return_value={"et": encrypted}) as send:
            result = get_xcode_token(self.session, self.anisette)

        self.assertEqual(result.token, "synthetic-xcode-token")
        self.assertEqual(result.expires, 1790000000000)
        self.assertNotIn(result.token, repr(result))
        args = send.call_args.args
        self.assertEqual(args[1]["o"], "apptokens")
        self.assertEqual(args[1]["u"], self.session.dsid)
        self.assertEqual(args[1]["app"], [XCODE_AUTH_APP])
        self.assertEqual(args[1]["c"], self.session.continuation)
        self.assertEqual(args[1]["t"], self.session.idms_token)

    def test_bare_xml_token_plist_is_accepted(self):
        with patch(
            "apple_account.send_gsa_request",
            return_value={"et": self.encrypted_token(bare=True)},
        ):
            result = get_xcode_token(self.session, self.anisette)
        self.assertEqual(result.expires, 1790000000000)

    def test_tampered_token_is_rejected(self):
        encrypted = bytearray(self.encrypted_token())
        encrypted[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, "authenticate"):
            decrypt_app_token(self.key, bytes(encrypted))

    def test_incomplete_session_cannot_request_token(self):
        self.session.session_key = None
        with self.assertRaisesRegex(RuntimeError, "Complete Apple authentication"):
            get_xcode_token(self.session, self.anisette)

    def test_apple_session_retries_only_connection_failures(self):
        http = apple_http_session()
        try:
            retries = http.get_adapter("https://gsa.apple.com/").max_retries
            self.assertEqual(retries.connect, 2)
            self.assertEqual(retries.read, 0)
            self.assertEqual(retries.status, 0)
            self.assertEqual(retries.other, 0)
        finally:
            http.close()

    def test_gsa_connection_error_explains_dns_failure(self):
        http = Mock()
        http.post.side_effect = requests.exceptions.ConnectionError("DNS failure")
        with self.assertRaisesRegex(RuntimeError, "Check your DNS"):
            send_gsa_request(http, {"o": "init"}, self.anisette)


if __name__ == "__main__":
    unittest.main()

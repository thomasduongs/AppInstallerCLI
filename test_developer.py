import plistlib
import unittest
from unittest.mock import Mock

from apple_account import AnisetteData, AppleSession, XcodeToken
from developer import format_developer_account, get_developer_account


class DeveloperAccountTests(unittest.TestCase):
    def setUp(self):
        self.session = AppleSession(
            apple_id="test@example.invalid",
            dsid="123456",
            idms_token="idms-secret",
            payload={},
            auth_type=None,
            session_key=b"key",
            continuation=b"continuation",
        )
        self.token = XcodeToken("xcode-secret", 1790000000000)
        self.anisette = AnisetteData(
            headers={
                "X-Apple-Locale": "en_US",
                "X-Apple-I-Client-Time": "2026-09-16T00:00:00Z",
                "X-Apple-I-TimeZone": "UTC",
                "X-Apple-I-MD": "otp",
                "X-Apple-I-MD-LU": "user",
                "X-Apple-I-MD-M": "machine",
                "X-Apple-I-MD-RINFO": "84215040",
                "X-Mme-Device-Id": "device",
                "X-Apple-I-SRL-NO": "serial",
            },
            client_info="client",
        )

    def response(self, payload):
        response = Mock()
        response.content = plistlib.dumps(payload)
        return response

    def test_account_uses_view_developer_then_list_teams(self):
        http = Mock()
        http.post.side_effect = [
            self.response({"resultCode": 0, "developer": {
                "firstName": "Thomas", "lastName": "Duong",
            }}),
            self.response({"resultCode": 0, "teams": [{
                "name": "Thomas Duong (Personal Team)", "teamId": "ABC123XYZ",
            }]}),
        ]

        account = get_developer_account(self.session, self.token, self.anisette, http)

        self.assertEqual(
            format_developer_account(account),
            "Developer Account\n-----------------\nName: Thomas Duong\n\n"
            "Teams:\n[0] Thomas Duong (Personal Team)\n    ID: ABC123XYZ",
        )
        self.assertEqual(http.post.call_count, 2)
        first, second = http.post.call_args_list
        self.assertTrue(first.args[0].endswith("/viewDeveloper.action"))
        self.assertTrue(second.args[0].endswith("/listTeams.action"))
        self.assertEqual(first.kwargs["params"], {"clientId": "XABBG36SBA"})
        self.assertEqual(first.kwargs["headers"]["X-Apple-GS-Token"], "xcode-secret")
        self.assertEqual(first.kwargs["headers"]["X-Apple-I-Identity-Id"], "123456")
        body = plistlib.loads(first.kwargs["data"])
        self.assertEqual(body["clientId"], "XABBG36SBA")
        self.assertEqual(body["protocolVersion"], "QH65B2")
        self.assertIn("requestId", body)

    def test_service_error_does_not_request_teams(self):
        http = Mock()
        http.post.return_value = self.response({
            "resultCode": 1100, "userString": "Authentication expired",
        })
        with self.assertRaisesRegex(RuntimeError, "Authentication expired"):
            get_developer_account(self.session, self.token, self.anisette, http)
        self.assertEqual(http.post.call_count, 1)

    def test_missing_team_id_is_rejected(self):
        http = Mock()
        http.post.side_effect = [
            self.response({"developer": {"name": "Thomas Duong"}}),
            self.response({"teams": [{"name": "Personal Team"}]}),
        ]
        with self.assertRaisesRegex(RuntimeError, "without a name or ID"):
            get_developer_account(self.session, self.token, self.anisette, http)


if __name__ == "__main__":
    unittest.main()

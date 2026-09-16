import io
import plistlib
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock

from apple_account import AnisetteData, AppleSession, XcodeToken
from developer import DeveloperClient, DeveloperTeam
from main import select_connected_device, select_developer_team
from provisioning import ProvisioningManager, RegisteredAppID, RegisteredDevice


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.team = DeveloperTeam("Personal Team", "ABC123XYZ")
        self.session = AppleSession(
            apple_id="test@example.invalid", dsid="123456", idms_token="secret",
            payload={}, auth_type=None, session_key=b"key", continuation=b"c",
        )
        self.token = XcodeToken("xcode-secret", 1790000000000)
        self.anisette = AnisetteData(
            headers={"X-Apple-Locale": "en_US"}, client_info="client"
        )

    @staticmethod
    def response(payload):
        result = Mock()
        result.content = plistlib.dumps(payload)
        return result

    def test_registered_device_is_not_added_again(self):
        developer = Mock()
        existing = RegisteredDevice("00008120-ABC", "My iPhone", "42")
        developer.get_devices.return_value = [existing]
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()):
            result = manager.register_device("00008120-abc", "New name")

        self.assertIs(result, existing)
        developer.get_devices.assert_called_once_with(self.team)
        developer.register_device.assert_not_called()

    def test_missing_device_is_registered_once(self):
        developer = Mock()
        developer.get_devices.return_value = []
        expected = RegisteredDevice("00008120-ABC", "My iPhone")
        developer.register_device.return_value = expected
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()) as output:
            result = manager.register_device("00008120-ABC", "My iPhone")

        self.assertIs(result, expected)
        self.assertIn("Checking registration...", output.getvalue())
        self.assertIn("Device registered successfully.", output.getvalue())
        developer.register_device.assert_called_once_with(
            team=self.team, udid="00008120-ABC", name="My iPhone"
        )

    def test_developer_client_uses_team_scoped_device_actions(self):
        http = Mock()
        http.post.side_effect = [
            self.response({"resultCode": 0, "devices": []}),
            self.response({"resultCode": 0, "device": {
                "deviceNumber": "00008120-ABC", "name": "My iPhone", "deviceId": "42",
            }}),
        ]
        developer = DeveloperClient(self.session, self.token, self.anisette, http)

        self.assertEqual(developer.get_devices(self.team), [])
        registered = developer.register_device(self.team, "00008120-ABC", "My iPhone")

        self.assertEqual(registered.identifier, "00008120-ABC")
        self.assertEqual(registered.device_id, "42")
        list_call, add_call = http.post.call_args_list
        self.assertTrue(list_call.args[0].endswith("/ios/listDevices.action"))
        self.assertEqual(plistlib.loads(list_call.kwargs["data"])["teamId"], "ABC123XYZ")
        self.assertTrue(add_call.args[0].endswith("/ios/addDevice.action"))
        add_body = plistlib.loads(add_call.kwargs["data"])
        self.assertEqual(add_body["teamId"], "ABC123XYZ")
        self.assertEqual(add_body["deviceNumber"], "00008120-ABC")
        self.assertEqual(add_body["name"], "My iPhone")

    def test_ambiguous_targets_require_explicit_selection(self):
        devices = [SimpleNamespace(serial="ONE"), SimpleNamespace(serial="TWO")]
        with self.assertRaisesRegex(RuntimeError, "specify --udid"):
            select_connected_device(devices)
        self.assertEqual(select_connected_device(devices, "two").serial, "TWO")
        with self.assertRaisesRegex(RuntimeError, "specify --team-id"):
            select_developer_team([self.team, DeveloperTeam("Other", "OTHER")])
        self.assertIs(select_developer_team([self.team], "abc123xyz"), self.team)

    def test_existing_app_id_is_reused(self):
        developer = Mock()
        existing = RegisteredAppID("com.example.myapp", "My App", "123")
        developer.get_app_ids.return_value = [existing]
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()) as output:
            result = manager.get_or_create_app_id("com.example.MyApp", "New name")

        self.assertIs(result, existing)
        self.assertIn("App ID already exists.", output.getvalue())
        developer.get_app_ids.assert_called_once_with(self.team)
        developer.register_app_id.assert_not_called()

    def test_missing_app_id_is_registered_once(self):
        developer = Mock()
        developer.get_app_ids.return_value = []
        expected = RegisteredAppID("com.example.myapp", "My App", "123")
        developer.register_app_id.return_value = expected
        manager = ProvisioningManager(developer, self.team)

        with redirect_stdout(io.StringIO()) as output:
            result = manager.get_or_create_app_id("com.example.myapp", "My App")

        self.assertIs(result, expected)
        self.assertIn("App ID registered successfully.", output.getvalue())
        developer.register_app_id.assert_called_once_with(
            team=self.team, bundle_id="com.example.myapp", name="My App"
        )

    def test_developer_client_uses_team_scoped_app_id_actions(self):
        http = Mock()
        http.post.side_effect = [
            self.response({"resultCode": 0, "appIds": []}),
            self.response({"resultCode": 0, "appId": {
                "identifier": "com.example.myapp", "name": "My App", "appIdId": "123",
            }}),
        ]
        developer = DeveloperClient(self.session, self.token, self.anisette, http)

        self.assertEqual(developer.get_app_ids(self.team), [])
        created = developer.register_app_id(self.team, "com.example.myapp", "My App")

        self.assertEqual(created.bundle_identifier, "com.example.myapp")
        self.assertEqual(created.app_id, "123")
        list_call, add_call = http.post.call_args_list
        self.assertTrue(list_call.args[0].endswith("/ios/listAppIds.action"))
        self.assertEqual(plistlib.loads(list_call.kwargs["data"])["teamId"], "ABC123XYZ")
        self.assertTrue(add_call.args[0].endswith("/ios/addAppId.action"))
        add_body = plistlib.loads(add_call.kwargs["data"])
        self.assertEqual(add_body["teamId"], "ABC123XYZ")
        self.assertEqual(add_body["identifier"], "com.example.myapp")
        self.assertEqual(add_body["name"], "My App")

    def test_developer_client_downloads_team_profile_by_app_id(self):
        http = Mock()
        http.post.return_value = self.response({
            "resultCode": 0,
            "provisioningProfile": {
                "name": "My App Profile",
                "provisioningProfileId": "PROFILE123",
                "encodedProfile": b"synthetic-cms",
            },
        })
        developer = DeveloperClient(self.session, self.token, self.anisette, http)
        app_id = RegisteredAppID("com.example.myapp", "My App", "APP123")

        profile = developer.download_team_provisioning_profile(self.team, app_id)

        self.assertEqual(profile.data, b"synthetic-cms")
        self.assertEqual(profile.identifier, "PROFILE123")
        call = http.post.call_args
        self.assertTrue(call.args[0].endswith("/ios/downloadTeamProvisioningProfile.action"))
        body = plistlib.loads(call.kwargs["data"])
        self.assertEqual(body["teamId"], self.team.identifier)
        self.assertEqual(body["appIdId"], "APP123")


if __name__ == "__main__":
    unittest.main()

import argparse
import asyncio
from device import get_devices, show_devices
from installer import install_ipa
from getpass import getpass
from apple_account import AppleAccount, get_anisette_data, get_xcode_token
from certificate import get_or_create_certificate
from credentials import load_credentials, save_credentials
from developer import DeveloperClient, get_developer_account, format_developer_account
from ipa import read_ipa
from provisioning import ProvisioningManager
from signer import sign_ipa


def select_connected_device(devices, udid=None):
    unique = {device.serial.upper(): device for device in devices}
    if udid:
        selected = unique.get(udid.upper())
        if selected is None:
            raise RuntimeError(f"Device {udid} is not connected.")
        return selected
    if not unique:
        raise RuntimeError("No iOS device is connected.")
    if len(unique) != 1:
        raise RuntimeError("Multiple devices are connected; specify --udid.")
    return next(iter(unique.values()))


def select_developer_team(teams, team_id=None):
    if team_id:
        for team in teams:
            if team.identifier.upper() == team_id.upper():
                return team
        raise RuntimeError(f"Team {team_id} is not available for this account.")
    if not teams:
        raise RuntimeError("This developer account has no teams.")
    if len(teams) != 1:
        raise RuntimeError("Multiple developer teams are available; specify --team-id.")
    return teams[0]

def main():
    parser = argparse.ArgumentParser(
        prog="freshapp",
        description="lighteweight ios sideloader"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    subparsers.add_parser(
        "devices",
        help="lists devices"
    )

    info_parser = subparsers.add_parser(
        "info",
        description="gets information about IPA"
    )

    install_parser = subparsers.add_parser(
        "install",
        description="installs IPA into device"
    )

    subparsers.add_parser(
        "login",
        help="authenticate with Apple"
    )

    subparsers.add_parser(
        "account",
        help="show your Apple developer account and teams"
    )

    register_parser = subparsers.add_parser(
        "register-device",
        help="register a connected iOS device with a developer team if needed"
    )
    register_parser.add_argument("--udid", help="choose a connected device")
    register_parser.add_argument("--team-id", help="choose a developer team")
    register_parser.add_argument("--name", default="FreshAppleCTL iPhone",
                                 help="name used when registering a new device")

    app_parser = subparsers.add_parser(
        "register-app",
        help="register an IPA's bundle ID with a developer team if needed"
    )
    app_parser.add_argument("ipa", help="path to IPA")
    app_parser.add_argument("--team-id", help="choose a developer team")

    certificate_parser = subparsers.add_parser(
        "certificate",
        help="create or reuse a local iOS development signing identity"
    )
    certificate_parser.add_argument("--team-id", help="choose a developer team")

    provision_parser = subparsers.add_parser(
        "provision",
        help="prepare an IPA's development provisioning profile"
    )
    provision_parser.add_argument("ipa", help="path to IPA")
    provision_parser.add_argument("--udid", help="choose a connected device")
    provision_parser.add_argument("--team-id", help="choose a developer team")
    provision_parser.add_argument(
        "--device-name", default="FreshAppleCTL iPhone",
        help="name used if the device must be registered"
    )

    sign_parser = subparsers.add_parser(
        "sign", help="provision and sign an IPA for a connected iPhone"
    )
    sign_parser.add_argument("ipa", help="path to IPA")
    sign_parser.add_argument("--output", help="new signed IPA path")
    sign_parser.add_argument("--udid", help="choose a connected device")
    sign_parser.add_argument("--team-id", help="choose a developer team")
    sign_parser.add_argument("--device-name", default="FreshAppleCTL iPhone",
                             help="name used if the device must be registered")
    sign_parser.add_argument("--install", action="store_true",
                             help="install the signed IPA on the selected device")

    info_parser.add_argument(
        "ipa",
        help="path to IPA"
    )

    install_parser.add_argument(
        "ipa",
        help="path to IPA"
    )

    args = parser.parse_args()

    if(args.command == "devices"):
        show_devices()
    elif(args.command == "info"):
        metadata = read_ipa(args.ipa)
        print(f"Name: {metadata.display_name}")
        print(f"Bundle ID: {metadata.bundle_identifier}")
        print(f"Executable: {metadata.executable}")
        print(f"Version: {metadata.short_version}")
    elif(args.command == "install"):
        install_ipa(args.ipa)
    elif(args.command in ("login", "account", "register-device", "register-app", "certificate", "provision", "sign")):
        connected_device = None
        ipa_metadata = None
        if args.command in ("register-device", "provision", "sign"):
            connected_device = select_connected_device(
                asyncio.run(get_devices()), args.udid
            )
            print(f"Connected device: {connected_device.serial}")
        if args.command in ("register-app", "provision", "sign"):
            print("Reading IPA...")
            ipa_metadata = read_ipa(args.ipa)
            print(f"Name: {ipa_metadata.display_name}")
            print(f"Bundle ID: {ipa_metadata.bundle_identifier}")

        APPLE_ID, PASSWORD = load_credentials()
        if APPLE_ID is None:
            APPLE_ID = input("Apple ID: ").strip()

        if PASSWORD is None:
            PASSWORD = getpass("Password: ")

        account = AppleAccount()

        session = account.login(
            APPLE_ID,
            PASSWORD
        )

        print("Requesting Xcode authentication token...")
        anisette = get_anisette_data()
        xcode_token = get_xcode_token(
            session,
            anisette
        )

        save_credentials(
            APPLE_ID,
            PASSWORD
        )

        if args.command in ("account", "register-device", "register-app", "certificate", "provision", "sign"):
            developer_account = get_developer_account(
                session, xcode_token, anisette
            )
            if args.command == "account":
                print()
                print(format_developer_account(developer_account))
            else:
                team = select_developer_team(developer_account.teams, args.team_id)
                print(f"Using team: {team.name} ({team.identifier})")
                developer = DeveloperClient(session, xcode_token, anisette)
                if args.command == "certificate":
                    get_or_create_certificate(developer, team)
                else:
                    manager = ProvisioningManager(developer, team)
                    if args.command == "register-device":
                        manager.register_device(connected_device.serial, args.name)
                    elif args.command == "register-app":
                        manager.get_or_create_app_id(
                            ipa_metadata.bundle_identifier, ipa_metadata.display_name
                        )
                    else:
                        app_id = manager.get_or_create_app_id(
                            ipa_metadata.bundle_identifier, ipa_metadata.display_name
                        )
                        device = manager.register_device(
                            connected_device.serial, args.device_name
                        )
                        certificate_path = get_or_create_certificate(developer, team)
                        profile, saved_path = manager.get_or_create_profile(
                            app_id, certificate_path, device,
                            ipa_metadata.bundle_identifier,
                        )
                        print(f"Saved: {saved_path}")
                        if args.command == "sign":
                            signed_path = sign_ipa(
                                args.ipa, saved_path, certificate_path,
                                team.identifier, connected_device.serial, args.output,
                            )
                            print(f"Signed IPA: {signed_path}")
                            if args.install and not install_ipa(signed_path, connected_device.serial):
                                raise RuntimeError("Signed IPA installation failed.")
        else:
            print()
            print("Logged in.")
            print(f"Apple ID: {session.apple_id}")
            print(f"DSID: {session.dsid}")
            print("Xcode authentication successful.")

if __name__ == "__main__":
    main()

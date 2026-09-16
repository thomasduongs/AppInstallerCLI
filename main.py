import argparse
from device import show_devices
from installer import install_ipa
from getpass import getpass
from apple_account import AppleAccount
from credentials import load_credentials, save_credentials

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
    elif(args.command == "install"):
        install_ipa(args.ipa)
    elif(args.command == "login"):
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

        save_credentials(
            APPLE_ID,
            PASSWORD
        )

        print()
        print("Logged in.")
        print(f"Apple ID: {session.apple_id}")
        print(f"DSID: {session.dsid}")

if __name__ == "__main__":
    main()
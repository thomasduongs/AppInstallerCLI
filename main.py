import argparse

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

    info_parser.add_argument(
        "ipa",
        help="path to IPA"
    )

    args = parser.parse_args()

    if(args.command == "devices"):
        print("hi")


main()
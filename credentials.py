from pathlib import Path
import json
import keyring


CONFIG_DIR = Path.home() / ".freshapplctl"
CONFIG_FILE = CONFIG_DIR / "config.json"

KEYCHAIN_SERVICE = "FreshAppleCTL"


def save_credentials(apple_id: str, password: str):
    CONFIG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Store Apple ID in normal config
    config = {
        "apple_id": apple_id
    }

    CONFIG_FILE.write_text(
        json.dumps(config, indent=4)
    )

    # Store password securely in macOS Keychain
    keyring.set_password(
        KEYCHAIN_SERVICE,
        apple_id,
        password
    )


def load_credentials():
    if not CONFIG_FILE.exists():
        return None, None

    config = json.loads(
        CONFIG_FILE.read_text()
    )

    apple_id = config.get("apple_id")

    if not apple_id:
        return None, None

    password = keyring.get_password(
        KEYCHAIN_SERVICE,
        apple_id
    )

    return apple_id, password


def delete_credentials():
    if not CONFIG_FILE.exists():
        return

    config = json.loads(
        CONFIG_FILE.read_text()
    )

    apple_id = config.get("apple_id")

    if apple_id:
        try:
            keyring.delete_password(
                KEYCHAIN_SERVICE,
                apple_id
            )
        except keyring.errors.PasswordDeleteError:
            pass

    CONFIG_FILE.unlink()
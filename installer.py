from pathlib import Path
import subprocess

def install_ipa(ipa_path, udid=None):
    ipa = Path(ipa_path)

    if not ipa.exists:
        print("ipa doesn't exist")
        return False

    if ipa.suffix != ".ipa":
        print("file isn't an ipa")
        return False

    command = [
        "pymobiledevice3",
        "apps",
        "install",
        str(ipa)
    ]

    if udid:
        command.extend(["--udid", udid])

    print(f"installing {ipa.name}...")

    result = subprocess.run(command)

    if result.returncode == 0:
        print("installation succesful")
        return True

    print("installation failed")
    return False
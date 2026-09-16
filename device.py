import asyncio
from pymobiledevice3.usbmux import list_devices

async def get_devices():
    devices = await list_devices()
    return devices

def show_devices():
    devices = asyncio.run(get_devices())

    if not devices:
        print("No IOS devices detected")
        return

    print(f"Found {len(devices)} device/s:\n")

    for device in devices:
        print(f"UDID: {device.serial}")
        print(f"Connection: {device.connection_type}\n")
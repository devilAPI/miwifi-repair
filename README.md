# miwifi-repair

Cross-platform CLI tool for flashing/recovering Xiaomi (Mi) routers via TFTP — a reverse-engineered replacement for the Windows-only `MIWIFIRepairTool.exe`. Supports Linux, macOS, and Windows.

## What it does

When a Xiaomi router is in recovery mode, it requests firmware over TFTP. This tool:

1. Configures your Ethernet interface with a static IP (192.168.31.100)
2. Runs a DHCP/BOOTP server to assign the router its expected IP
3. Serves the firmware file over TFTP
4. Restores your network config on exit

No dependencies beyond Python 3.

## Usage

```bash
# Linux / macOS
sudo ./miwifi-repair.py <firmware.bin> -i <interface>

# Windows (run terminal as Administrator)
python miwifi-repair.py <firmware.bin> -i <interface>
```

### Examples

```bash
# Linux
sudo ./miwifi-repair.py miwifi_r4ac_all_c4b35_2.18.28.bin -i enp0s31f6

# macOS
sudo ./miwifi-repair.py miwifi_r4ac_all_c4b35_2.18.28.bin -i en0

# Windows
python miwifi-repair.py miwifi_r4ac_all_c4b35_2.18.28.bin -i Ethernet
```

### Options

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Network interface connected to the router |
| `--server-ip` | IP to assign to this machine (default: 192.168.31.100) |
| `--router-ip` | Expected router IP (default: 192.168.31.1) |
| `--no-restore` | Don't restore network config on exit |

## How to enter recovery mode

1. Unplug the router's power
2. Hold the **reset** button (pinhole on the back)
3. While holding reset, plug power back in
4. Hold for ~10 seconds until the LED blinks rapidly
5. Release reset — the router is now waiting for firmware via TFTP

## Tested models

- Mi Router 4A 100M (R4AC)

Should work with any Xiaomi router that supports TFTP recovery (most models do).

## Background

The original `MIWIFIRepairTool.x86.exe` is a Windows GUI app built on TFTPD32 v4.61 with libcurl. It was reverse-engineered via static analysis (string extraction, API/protocol identification) and reimplemented as a pure Python CLI.

## License

MIT

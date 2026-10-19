#!/usr/bin/env python3
"""
MIWIFI Repair Tool

Recovers/reflashes Xiaomi routers via TFTP+DHCP, replicating the
functionality of MIWIFIRepairTool.x86.exe.

Supports Linux, macOS, and Windows.

Usage:
  sudo ./miwifi-repair.py <firmware.bin> -i <interface>       (Linux/macOS)
  python miwifi-repair.py <firmware.bin> -i <interface>       (Windows, as admin)

The router must be in recovery mode (hold reset while powering on).
"""

import argparse
import ipaddress
import os
import platform
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

PLATFORM = platform.system()  # "Linux", "Darwin", "Windows"

ROUTER_IP = "192.168.31.1"
SERVER_IP = "192.168.31.100"
SUBNET_MASK = "255.255.255.0"
TFTP_PORT = 69
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
TFTP_BLOCK_SIZE = 512
TFTP_TIMEOUT = 5
TFTP_MAX_RETRIES = 20


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def check_root():
    if PLATFORM == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: this tool requires Administrator privileges.")
                print("Right-click your terminal and choose 'Run as administrator'.")
                sys.exit(1)
        except AttributeError:
            pass
    else:
        if os.geteuid() != 0:
            print("Error: this tool requires root privileges.")
            print("Run with: sudo ./miwifi-repair.py ...")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Interface configuration
# ---------------------------------------------------------------------------

def configure_interface(iface, ip, mask):
    print(f"Configuring {iface} with {ip}/{mask}")
    prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen

    if PLATFORM == "Linux":
        subprocess.run(
            ["ip", "addr", "flush", "dev", iface],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["ip", "addr", "add", f"{ip}/{prefix_len}", "dev", iface],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["ip", "link", "set", iface, "up"],
            check=True, capture_output=True,
        )
    elif PLATFORM == "Darwin":
        subprocess.run(
            ["ifconfig", iface, "inet", ip, "netmask", mask],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["ifconfig", iface, "up"],
            check=True, capture_output=True,
        )
    elif PLATFORM == "Windows":
        subprocess.run(
            ["netsh", "interface", "ip", "set", "address",
             f"name={iface}", "static", ip, mask],
            check=True, capture_output=True,
        )


def restore_interface(iface):
    print(f"\nRestoring {iface} to DHCP...")
    if PLATFORM == "Linux":
        subprocess.run(
            ["ip", "addr", "flush", "dev", iface],
            capture_output=True,
        )
        for cmd in [
            ["dhclient", iface],
            ["dhcpcd", iface],
            ["networkctl", "reconfigure", iface],
        ]:
            try:
                subprocess.run(cmd, capture_output=True, timeout=10)
                break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
    elif PLATFORM == "Darwin":
        subprocess.run(
            ["ipconfig", "set", iface, "DHCP"],
            capture_output=True,
        )
    elif PLATFORM == "Windows":
        subprocess.run(
            ["netsh", "interface", "ip", "set", "address",
             f"name={iface}", "dhcp"],
            capture_output=True,
        )


# ---------------------------------------------------------------------------
# ARP flush
# ---------------------------------------------------------------------------

def flush_arp(ip):
    if PLATFORM == "Linux":
        subprocess.run(["ip", "neigh", "flush", "to", ip], capture_output=True)
    elif PLATFORM == "Darwin":
        subprocess.run(["arp", "-d", ip], capture_output=True)
    elif PLATFORM == "Windows":
        subprocess.run(["arp", "-d", ip], capture_output=True)


# ---------------------------------------------------------------------------
# Network manager control (Linux-only, no-ops on other platforms)
# ---------------------------------------------------------------------------

def stop_network_manager(iface):
    if PLATFORM != "Linux":
        return []

    actions = []

    r = subprocess.run(
        ["nmcli", "device", "set", iface, "managed", "no"],
        capture_output=True,
    )
    if r.returncode == 0:
        actions.append("nmcli_unmanaged")
        print(f"  Told NetworkManager to ignore {iface}")

    for client in ["dhclient", "dhcpcd"]:
        subprocess.run(["pkill", "-f", f"{client}.*{iface}"], capture_output=True)

    r = subprocess.run(
        ["networkctl", "forgo", iface],
        capture_output=True,
    )
    if r.returncode == 0:
        actions.append("networkctl_forgo")
        print(f"  Told systemd-networkd to ignore {iface}")

    return actions


def restore_network_manager(iface, actions):
    if "nmcli_unmanaged" in actions:
        subprocess.run(
            ["nmcli", "device", "set", iface, "managed", "yes"],
            capture_output=True,
        )
        print(f"  Returned {iface} to NetworkManager")
    if "networkctl_forgo" in actions:
        subprocess.run(
            ["networkctl", "reconfigure", iface],
            capture_output=True,
        )


# ---------------------------------------------------------------------------
# Firewall port management
# ---------------------------------------------------------------------------

def open_firewall_ports(iface=None):
    rules = []

    if PLATFORM == "Linux":
        for port, proto in [(67, "udp"), (68, "udp"), (69, "udp")]:
            r = subprocess.run(
                ["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                capture_output=True,
            )
            if r.returncode == 0:
                rules.append(("iptables", port, proto))

        if rules:
            print(f"  Opened firewall ports (iptables): 67, 68, 69/udp")
            return rules

        r = subprocess.run(
            ["nft", "add", "table", "inet", "miwifi_repair"],
            capture_output=True,
        )
        if r.returncode == 0:
            subprocess.run(
                ["nft", "add", "chain", "inet", "miwifi_repair", "input",
                 "{ type filter hook input priority -10 ; policy accept ; }"],
                capture_output=True,
            )
            for port in [67, 68, 69]:
                subprocess.run(
                    ["nft", "add", "rule", "inet", "miwifi_repair", "input",
                     "udp", "dport", str(port), "accept"],
                    capture_output=True,
                )
            rules.append(("nftables",))
            print(f"  Opened firewall ports (nftables): 67, 68, 69/udp")

    elif PLATFORM == "Darwin":
        anchor = "com.miwifi-repair"
        pf_rules = (
            f'pass in quick on {iface} proto udp from any to any port {{ 67, 68, 69 }}\n'
            if iface else
            'pass in quick proto udp from any to any port { 67, 68, 69 }\n'
        )
        anchor_file = "/tmp/miwifi_repair_pf.conf"
        try:
            with open(anchor_file, "w") as f:
                f.write(pf_rules)
            subprocess.run(
                ["pfctl", "-a", anchor, "-f", anchor_file],
                capture_output=True,
            )
            subprocess.run(["pfctl", "-e"], capture_output=True)
            rules.append(("pf", anchor, anchor_file))
            print(f"  Opened firewall ports (pf): 67, 68, 69/udp")
        except OSError:
            pass

    elif PLATFORM == "Windows":
        rule_name = "MIWIFIRepair_DHCP_TFTP"
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=allow",
             "protocol=UDP", "localport=67,68,69"],
            capture_output=True,
        )
        if r.returncode == 0:
            rules.append(("netsh", rule_name))
            print(f"  Opened firewall ports (Windows Firewall): 67, 68, 69/udp")

    return rules


def close_firewall_ports(rules):
    for rule in rules:
        if rule[0] == "iptables":
            _, port, proto = rule
            subprocess.run(
                ["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                capture_output=True,
            )
        elif rule[0] == "nftables":
            subprocess.run(
                ["nft", "delete", "table", "inet", "miwifi_repair"],
                capture_output=True,
            )
        elif rule[0] == "pf":
            _, anchor, anchor_file = rule
            subprocess.run(
                ["pfctl", "-a", anchor, "-F", "all"],
                capture_output=True,
            )
            try:
                os.unlink(anchor_file)
            except OSError:
                pass
        elif rule[0] == "netsh":
            _, rule_name = rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True,
            )


# ---------------------------------------------------------------------------
# DHCP Server
# ---------------------------------------------------------------------------

class DHCPServer(threading.Thread):
    """Minimal DHCP/BOOTP server that hands the router a known IP and
    points it at our TFTP server + boot filename."""

    def __init__(self, iface, server_ip, router_ip, boot_file):
        super().__init__(daemon=True)
        self.iface = iface
        self.server_ip = server_ip
        self.router_ip = router_ip
        self.boot_file = boot_file
        self.running = True
        self.served = 0

    def stop(self):
        self.running = False

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if PLATFORM == "Linux":
            sock.setsockopt(
                socket.SOL_SOCKET, 25, self.iface.encode()  # SO_BINDTODEVICE
            )
        elif PLATFORM == "Windows":
            sock.bind((self.server_ip, DHCP_SERVER_PORT))
        # macOS: bind to INADDR_ANY; with a single interface configured,
        # broadcast replies reach the right segment.

        if PLATFORM != "Windows":
            sock.bind(("0.0.0.0", DHCP_SERVER_PORT))

        sock.settimeout(1)
        print(f"DHCP server listening on {self.iface}:{DHCP_SERVER_PORT}")

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 240:
                continue

            op = data[0]
            if op != 1:  # BOOTREQUEST
                continue

            xid = data[4:8]
            client_mac = data[28:34]
            mac_str = ":".join(f"{b:02x}" for b in client_mac)

            msg_type = self._get_dhcp_msg_type(data)
            msg_name = {1: "DISCOVER", 3: "REQUEST"}.get(msg_type, f"type={msg_type}")
            print(f"DHCP {msg_name} from {mac_str}")

            reply = self._build_reply(xid, client_mac, msg_type)
            try:
                sock.sendto(reply, ("255.255.255.255", DHCP_CLIENT_PORT))
            except OSError as e:
                print(f"DHCP send error: {e}")
                continue

            reply_name = "OFFER" if msg_type == 1 else "ACK"
            print(f"DHCP {reply_name} -> {self.router_ip} (file: {self.boot_file})")
            self.served += 1

        sock.close()

    def _get_dhcp_msg_type(self, data):
        if len(data) <= 240:
            return 0
        if data[236:240] != b'\x63\x82\x53\x63':
            return 0
        i = 240
        while i < len(data):
            opt = data[i]
            if opt == 255:
                break
            if opt == 0:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            if opt == 53 and length >= 1:
                return data[i + 2]
            i += 2 + length
        return 0

    def _build_reply(self, xid, client_mac, request_type):
        server_ip = socket.inet_aton(self.server_ip)
        your_ip = socket.inet_aton(self.router_ip)

        pkt = bytearray(300)
        pkt[0] = 2  # BOOTREPLY
        pkt[1] = 1  # Ethernet
        pkt[2] = 6  # HW addr length
        pkt[3] = 0  # Hops
        pkt[4:8] = xid
        pkt[16:20] = your_ip      # yiaddr
        pkt[20:24] = server_ip    # siaddr (TFTP server)
        pkt[28:34] = client_mac

        boot_bytes = self.boot_file.encode("ascii")[:127]
        pkt[108:108 + len(boot_bytes)] = boot_bytes

        pkt[236:240] = b'\x63\x82\x53\x63'

        opts = bytearray()
        reply_type = 2 if request_type == 1 else 5
        opts += bytes([53, 1, reply_type])
        opts += bytes([54, 4]) + server_ip
        opts += bytes([1, 4]) + socket.inet_aton(SUBNET_MASK)
        opts += bytes([3, 4]) + server_ip
        opts += bytes([51, 4]) + struct.pack("!I", 3600)
        opts += bytes([66, 4]) + server_ip
        opts += bytes([67, len(boot_bytes)]) + boot_bytes
        opts += bytes([255])

        pkt[240:240 + len(opts)] = opts
        return bytes(pkt[:240 + len(opts)])


# ---------------------------------------------------------------------------
# TFTP Server
# ---------------------------------------------------------------------------

class TFTPServer(threading.Thread):
    """Minimal TFTP server that serves exactly one file."""

    def __init__(self, server_ip, filepath):
        super().__init__(daemon=True)
        self.server_ip = server_ip
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.filesize = os.path.getsize(filepath)
        self.running = True
        self.transfer_complete = threading.Event()

    def stop(self):
        self.running = False

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        sock.bind((self.server_ip, TFTP_PORT))
        print(f"TFTP server listening on {self.server_ip}:{TFTP_PORT}")
        print(f"Serving: {self.filename} ({self.filesize:,} bytes)")

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 4:
                continue

            opcode = struct.unpack("!H", data[:2])[0]
            if opcode == 1:  # RRQ (Read Request)
                parts = data[2:].split(b'\x00')
                req_file = parts[0].decode("ascii", errors="replace")
                mode = parts[1].decode("ascii", errors="replace") if len(parts) > 1 else "octet"
                print(f"TFTP RRQ: '{req_file}' mode={mode} from {addr[0]}:{addr[1]}")
                t = threading.Thread(
                    target=self._handle_read, args=(addr,), daemon=True
                )
                t.start()
            else:
                self._send_error(sock, addr, 4, "Illegal operation")

        sock.close()

    def _handle_read(self, client_addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TFTP_TIMEOUT)

        try:
            with open(self.filepath, "rb") as f:
                block = 1
                total_sent = 0
                start_time = time.time()

                while self.running:
                    chunk = f.read(TFTP_BLOCK_SIZE)

                    pkt = struct.pack("!HH", 3, block) + chunk
                    retries = 0

                    while retries < TFTP_MAX_RETRIES and self.running:
                        sock.sendto(pkt, client_addr)
                        try:
                            ack, _ = sock.recvfrom(512)
                            if len(ack) >= 4:
                                ack_op = struct.unpack("!H", ack[:2])[0]
                                ack_block = struct.unpack("!H", ack[2:4])[0]
                                if ack_op == 4 and ack_block == block:
                                    break
                                if ack_op == 5:  # ERROR
                                    msg = ack[4:].split(b'\x00')[0].decode(errors="replace")
                                    print(f"TFTP error from client: {msg}")
                                    return
                        except socket.timeout:
                            retries += 1
                            if retries < TFTP_MAX_RETRIES:
                                print(f"  Timeout on block {block}, retry {retries}")
                    else:
                        if not self.running:
                            return
                        print(f"TFTP: max retries reached on block {block}, aborting")
                        return

                    total_sent += len(chunk)
                    pct = min(100, total_sent * 100 // self.filesize) if self.filesize > 0 else 100
                    speed = total_sent / (time.time() - start_time) if time.time() > start_time else 0
                    print(
                        f"\r  Transfer: {pct}% "
                        f"({total_sent:,}/{self.filesize:,} bytes) "
                        f"{speed / 1024:.0f} KB/s",
                        end="", flush=True,
                    )

                    if len(chunk) < TFTP_BLOCK_SIZE:
                        elapsed = time.time() - start_time
                        print(
                            f"\n  Transfer complete: {total_sent:,} bytes "
                            f"in {elapsed:.1f}s "
                            f"({total_sent / elapsed / 1024:.0f} KB/s)"
                        )
                        self.transfer_complete.set()
                        return

                    block = (block + 1) & 0xFFFF
        except FileNotFoundError:
            self._send_error(sock, client_addr, 1, "File not found")
        except PermissionError:
            self._send_error(sock, client_addr, 2, "Access violation")
        finally:
            sock.close()

    def _send_error(self, sock, addr, code, msg):
        pkt = struct.pack("!HH", 5, code) + msg.encode() + b'\x00'
        sock.sendto(pkt, addr)


# ---------------------------------------------------------------------------
# Interface listing
# ---------------------------------------------------------------------------

def list_interfaces():
    if PLATFORM == "Linux":
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True,
        )
        ifaces = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(": ")
            if len(parts) >= 2:
                name = parts[1].split("@")[0]
                if name != "lo":
                    ifaces.append(name)
        return ifaces

    elif PLATFORM == "Darwin":
        result = subprocess.run(
            ["ifconfig", "-l"],
            capture_output=True, text=True,
        )
        return [
            i for i in result.stdout.strip().split()
            if i != "lo0" and not i.startswith("utun")
        ]

    elif PLATFORM == "Windows":
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True,
        )
        ifaces = []
        for line in result.stdout.strip().splitlines()[3:]:
            cols = line.split()
            if len(cols) >= 4:
                name = " ".join(cols[3:])
                ifaces.append(name)
        return ifaces

    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    platform_name = {"Linux": "Linux", "Darwin": "macOS", "Windows": "Windows"}.get(PLATFORM, PLATFORM)

    parser = argparse.ArgumentParser(
        description=f"MIWIFI Repair Tool for {platform_name} — flash Xiaomi router firmware via TFTP",
        epilog=(
            "Steps:\n"
            "  1. Connect your PC to the router via Ethernet\n"
            "  2. Run: sudo ./miwifi-repair.py firmware.bin -i eth0\n"
            "  3. Hold the reset button and power on the router\n"
            "  4. Wait for the transfer to complete (~2-5 minutes)\n"
            "  5. The router will reboot with the new firmware"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("firmware", help="Path to the firmware .bin file")
    parser.add_argument(
        "-i", "--interface",
        help="Network interface connected to the router (e.g., eth0, enp3s0, en0, Ethernet)",
    )
    parser.add_argument(
        "--server-ip", default=SERVER_IP,
        help=f"IP to assign to this machine (default: {SERVER_IP})",
    )
    parser.add_argument(
        "--router-ip", default=ROUTER_IP,
        help=f"Expected router IP (default: {ROUTER_IP})",
    )
    parser.add_argument(
        "--no-restore", action="store_true",
        help="Don't restore network config on exit",
    )
    args = parser.parse_args()

    check_root()

    firmware = os.path.abspath(args.firmware)
    if not os.path.isfile(firmware):
        print(f"Error: firmware file not found: {firmware}")
        sys.exit(1)

    filesize = os.path.getsize(firmware)
    if filesize == 0:
        print("Error: firmware file is empty")
        sys.exit(1)

    iface = args.interface
    if not iface:
        ifaces = list_interfaces()
        if not ifaces:
            print("Error: no network interfaces found")
            sys.exit(1)
        if PLATFORM == "Linux":
            eth = [i for i in ifaces if i.startswith(("eth", "enp", "eno", "ens"))]
        elif PLATFORM == "Darwin":
            eth = [i for i in ifaces if i.startswith("en")]
        elif PLATFORM == "Windows":
            eth = [i for i in ifaces if "ethernet" in i.lower() or "local area" in i.lower()]
        else:
            eth = []
        if len(eth) == 1:
            iface = eth[0]
        else:
            print("Available interfaces:")
            for i in (eth or ifaces):
                print(f"  {i}")
            print("\nSpecify one with -i, e.g.:", sys.argv[0], "firmware.bin -i", (eth or ifaces)[0])
            sys.exit(1)

    print("=" * 60)
    print(f"  MIWIFI Repair Tool for {platform_name}")
    print("=" * 60)
    print(f"  Firmware : {os.path.basename(firmware)} ({filesize:,} bytes)")
    print(f"  Interface: {iface}")
    print(f"  Server IP: {args.server_ip}")
    print(f"  Router IP: {args.router_ip}")
    print("=" * 60)
    print()
    print("Instructions:")
    print("  1. Connect this PC to the router's LAN port via Ethernet")
    print("  2. Hold the RESET button on the router")
    print("  3. While holding RESET, power on the router")
    print("  4. Keep holding RESET until the LED blinks rapidly")
    print("  5. Release RESET and wait for the firmware transfer")
    print()

    print("Preparing network...")
    nm_actions = stop_network_manager(iface)
    fw_rules = open_firewall_ports(iface)
    time.sleep(1)

    configure_interface(iface, args.server_ip, SUBNET_MASK)
    flush_arp(args.router_ip)

    dhcp = DHCPServer(iface, args.server_ip, args.router_ip, os.path.basename(firmware))
    tftp = TFTPServer(args.server_ip, firmware)

    def cleanup(signum=None, frame=None):
        print("\nShutting down...")
        dhcp.stop()
        tftp.stop()
        close_firewall_ports(fw_rules)
        if not args.no_restore:
            restore_network_manager(iface, nm_actions)
            restore_interface(iface)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    if PLATFORM != "Windows":
        signal.signal(signal.SIGTERM, cleanup)

    dhcp.start()
    tftp.start()

    print("Waiting for router to request firmware...")
    print("(Press Ctrl+C to abort)\n")

    while not tftp.transfer_complete.wait(timeout=1):
        pass

    print("\nFirmware sent successfully!")
    print("The router will now flash the firmware and reboot.")
    print("This may take 2-5 minutes. Do NOT power off the router.")
    print()

    time.sleep(5)
    cleanup()


if __name__ == "__main__":
    main()

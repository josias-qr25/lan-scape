import json
import socket
from scapy.all import *
from datetime import datetime
from time import sleep
from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()

def create_arp_packet(ip_range="192.168.1.0.0/24"):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    return packet

def get_mac_vendor(mac_address):
    try:
        return mac_lookup.lookup(mac_address)
    except Exception:
        return "Unknown"

def scan_lan(packet):
    from scapy.all import conf
    conf.verb = 0
    print("Scanning network with ARP requests...")

    results = srp(packet, timeout=3, verbose=0)[0]
    print(f"Received {len(results)} responses.\n")

    devices = []
    for sent , received in results:
        vendor = get_mac_vendor(received.hwsrc)
        devices.append({
            'ip': received.psrc, 
            'mac': received.hwsrc, 
            'vendor': vendor
        })

    return devices

def save_scan_results(devices, filename=None):
    while True:
        ssr_ans = input("Would you like to save the results to file? [Y/N] ").lower()
        if ssr_ans == "y" or ssr_ans == "yes":
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            if filename is None:
                filename = f"scan-results-{timestamp}.txt"
            with open(filename, "w") as file:
                for device in devices:
                    file.write(
                        f"{device['ip']} | {device['mac']} | {device['vendor']}\n"
                    )
            print(f"\nResults saved to {filename}\n")
            break
        elif ssr_ans == "n" or ssr_ans == "no":
            break
        else:
            print("Option unavailable.")

def scan_ip_ports():
    target_ip = input("Target IP: ").strip()
    port_range = input("Port Range (e.g., 20-80): ").strip()

    try:
        start_port, end_port = map(int, port_range.split("-"))
    except ValueError:
        print("Invalid range. Using default 1-1024.")
        start_port, end_port = 1, 1024

    print(f"\nScanning {target_ip} for open ports from {start_port} to {end_port}...\n")
    open_ports = []

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port} is OPEN.")
            open_ports.append(port)
        s.close()

    if open_ports:
        print(f"\nOpen Ports on {target_ip}: {open_ports}")
    else:
        print("No open ports found.")

def sniff_http():
    target_ip = input("Target IP: ").strip()
    target_port = input("Target Port: ").strip()

    def packet_callback(packet):
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                if any(x in payload for x in ["GET", "POST", "HTTP", "Host:", "User-Agent"]):
                    print("\n--- HTTP Packet ---")
                    print(payload)
            except Exception:
                pass

    print(f"Sniffing HTTP packets from {target_ip}:{target_port}... (Press Ctrl+C to stop)\n")
    sniff(
        filter=f"tcp and host {target_ip} and port {target_port}",
        prn=packet_callback,
        store=0
    )

def display_banner():
    print()
    print("██╗░░░░░░█████╗░███╗░░██╗░░░░░░░██████╗░█████╗░░█████╗░░░░██████╗░██╗░░░██╗")
    print("██║░░░░░██╔══██╗████╗░██║░░░░░░██╔════╝██╔══██╗██╔══██╗░░░██╔══██╗╚██╗░██╔╝")
    print("██║░░░░░███████║██╔██╗██║█████╗╚█████╗░██║░░╚═╝███████║░░░██████╔╝░╚████╔╝░")
    print("██║░░░░░██╔══██║██║╚████║╚════╝░╚═══██╗██║░░██╗██╔══██║░░░██╔═══╝░░░╚██╔╝░░")
    print("███████╗██║░░██║██║░╚███║░░░░░░██████╔╝╚█████╔╝██║░░██║██╗██║░░░░░░░░██║░░░")
    print("╚══════╝╚═╝░░╚═╝╚═╝░░╚══╝░░░░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝╚═╝░░░░░░░░╚═╝░░░")

def menu():
    while True:
        print()
        print("[1] Scan network for connected devices.")
        print("[2] Scan IP for open ports.")
        print("[3] Sniff HTTP packets from IP:Port.")
        print("[0] Exit")
        print()

        choice = input("[Option]: ").strip()

        if choice == "1":
            packet = create_arp_packet()
            devices = scan_lan(packet)
            for d in devices:
                print(f"{d['ip']} | {d['mac']} | {d['vendor']}")
            save_scan_results(devices)
        elif choice == "2":
            scan_ip_ports()
        elif choice == "3":
            sniff_http()
        elif choice == "0":
            print("Exiting... \n")
            break
        else:
            print("Option unavailable. Try again.\n")

def main():
    display_banner()
    menu()

if __name__ == "__main__":
    main()

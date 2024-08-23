import subprocess
import os
import re
from collections import namedtuple
import configparser

banner = r"""
   ___   ___   ___  __ 
  / _ \ / _ \ / _ \/_ |
 | | | | | | | | | || |
 | | | | | | | | | || |
 | |_| | |_| | |_| || |
  \___/ \___/ \___/ |_|   Veilwr4ith
"""

def fetch_windows_ssids():
    try:
        output = subprocess.check_output("netsh wlan show profiles", shell=True).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error fetching SSIDs from Windows: {e}")
        return []
    ssids = []
    profile_names = re.findall(r"All User Profile\s(.*)", output)
    for name in profile_names:
        ssid = name.strip().strip(":").strip()
        ssids.append(ssid)
    return ssids

def fetch_windows_wifi_passwords(show_details=1):
    ssids = fetch_windows_ssids()
    Profile = namedtuple("Profile", ["ssid", "cipher", "password"])
    profiles = []
    for ssid in ssids:
        try:
            details = subprocess.check_output(f"netsh wlan show profile \"{ssid}\" key=clear", shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            print(f"Error fetching details for SSID: {ssid}. Error: {e}")
            continue
        cipher_list = re.findall(r"Cipher\s(.*)", details)
        cipher = "/".join([c.strip().strip(":").strip() for c in cipher_list])
        password_list = re.findall(r"Key Content\s(.*)", details)
        password = password_list[0].strip().strip(":").strip() if password_list else "None"
        profile = Profile(ssid=ssid, cipher=cipher, password=password)
        if show_details >= 1:
            display_windows_profile(profile)
        profiles.append(profile)
    return profiles

def display_windows_profile(profile):
    print(f"{profile.ssid:25}{profile.cipher:15}{profile.password:50}")

def display_windows_profiles(show_details):
    print("-" * 80)
    print("SSID                     CIPHER(S)      PASSWORD")
    print("-" * 80)
    fetch_windows_wifi_passwords(show_details)
    print("-" * 80)

def fetch_linux_wifi_passwords(show_details=1):
    connections_path = "/etc/NetworkManager/system-connections/"
    fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
    Profile = namedtuple("Profile", [field.replace("-", "_") for field in fields])
    profiles = []
    for file in os.listdir(connections_path):
        file_path = os.path.join(connections_path, file)
        data = {k.replace("-", "_"): None for k in fields}
        config = configparser.ConfigParser(allow_no_value=True, delimiters=("=", ":"))
        config.optionxform = str
        try:
            with open(file_path, encoding='utf-8') as f:
                config.read_file(f)
        except (UnicodeDecodeError, IOError) as e:
            print(f"Error reading file {file_path}. Error: {e}")
            continue
        for section in config.sections():
            for key, value in config.items(section):
                if key in fields:
                    data[key.replace("-", "_")] = value
        profile = Profile(**data)
        if show_details >= 1:
            display_linux_profile(profile)
        profiles.append(profile)
    return profiles

def display_linux_profile(profile):
    print(f"{profile.ssid:25}{profile.auth_alg:10}{profile.key_mgmt:10}{profile.psk:50}")

def display_linux_profiles(show_details):
    print("-" * 80)
    print("SSID                     AUTH ALG   KEY-MGMT     PSK")
    print("-" * 80)
    fetch_linux_wifi_passwords(show_details)
    print("-" * 80)
    
def display_profiles(show_details=1):
    if os.name == "nt":
        display_windows_profiles(show_details)
    elif os.name == "posix":
        display_linux_profiles(show_details)
    else:
        raise NotImplementedError("This script only supports Windows or Linux.")

if __name__ == "__main__":
    print(banner)
    display_profiles()

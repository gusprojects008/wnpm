#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import json
import pathlib
import getpass
import pwd
import argparse
import hashlib
from typing import Dict, List, Any, Tuple
from terminal_colors import Colors

colors = Colors()

def PrivilegiesVerify() -> bool:
    return os.getuid() == 0

def SudoAuthentication():
    if not PrivilegiesVerify():
        print(colors("br", "\nThis program requires administrator privileges!\n"))
        try:
           subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
           sys.exit(0)
        except Exception:
            sys.exit(1)

def check_interface_exists(ifname: str) -> bool:
    return pathlib.Path(f"/sys/class/net/{ifname}").exists()

def check_active_interface(ifname: str) -> bool:
    try:
       state_path = pathlib.Path(f"/sys/class/net/{ifname}/operstate")
       return state_path.read_text().strip() == "up"
    except Exception:
        return False

def check_interface_ipv4(ifname: str) -> bool:
    try:
       result = subprocess.run(
         ["ip", "-4", "addr", "show", "dev", ifname],
         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, text=True
       )
       #return check_interface_exists(ifname) and check_active_interface(ifname) and "inet " in result.stdout
       return check_active_interface(ifname) and "inet " in result.stdout
    except Exception:
       return False

def set_interface_down(ifname: str) -> bool:
    print(colors("trying", f"Bringing interface {ifname} down..."))
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "flush", "dev", ifname], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(colors("ok", f"Interface {ifname} is down."))
        return True
    except subprocess.CalledProcessError as error:
        print(f"Failed to set interface {ifname} down: {error}")
        return False

def set_interface_up(ifname: str) -> bool:
    print(colors("trying", f"Bringing interface {ifname} up..."))
    try:
       subprocess.run(["ip", "link", "set", ifname, "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       print(colors("ok", f"Interface {ifname} is up."))
       return True
    except subprocess.CalledProcessError as error:
       print(f"Failed to set interface {ifname} up: {error}")
       return False

def get_mac_address(ifname: str) -> str:
    try:
        path = pathlib.Path(f"/sys/class/net/{ifname}/address")
        return path.read_text().strip()
    except Exception:
        raise ValueError(f"Could not read MAC address for {ifname}")

def _generate_hex_psk(ssid: str, psk: str) -> str:
    return hashlib.pbkdf2_hmac('sha1', psk.encode('utf-8'), ssid.encode('utf-8'), 4096, 32).hex()

def validate_interface_profile_data(CONFIG_DIR, ifname: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    print(colors("trying", f"Validating profile for {ifname}..."))

    if not ifname or not check_interface_exists(ifname):
       raise ValueError(f"Invalid or non-existent interface: {ifname}")

    hwaddr = get_mac_address(ifname)
    metric = profile_data.get("metric", 100)

    if not isinstance(metric, int) or metric <= 0:
       raise ValueError(f"Invalid metric for {ifname}: {metric}")

    ssid = profile_data.get("ssid", "").strip()
    if not ssid or len(ssid) > 32:
       raise ValueError(f"SSID for {ifname} must be between 1 and 32 characters.")

    psk = profile_data.get("psk", "").strip()
    if not (8 <= len(psk) <= 63):
       raise ValueError(f"PSK for {ifname} must be between 8 and 63 characters.")
    
    psk_hex = _generate_hex_psk(ssid, psk)

    wpa_supplicant_conf_path = CONFIG_DIR / f"wpa_supplicant_{ifname}.conf"
    dhcpcd_conf_path = CONFIG_DIR / f"dhcpcd_{ifname}.conf"

    return {
      "hwaddr": hwaddr,
      "metric": metric,
      "ssid": ssid,
      #"psk": psk,
      "psk_hex": psk_hex,
      "wpa_supplicant_conf_path": str(wpa_supplicant_conf_path),
      "dhcpcd_conf_path": str(dhcpcd_conf_path),
    }

def parse_config(CONFIG_DIR, config_file_path: pathlib.Path) -> List[Tuple[str, Dict[str, Any]]]:
    print(colors("trying", f"Parsing config file {config_file_path}..."))

    if not config_file_path or not config_file_path.is_file():
       print(colors("error", f"Configuration file not found at {config_file_path}"))
       sys.exit(1)
    try:
       with config_file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as error:
       print(colors("error", f"Error reading JSON config: {error}"))
       sys.exit(1)

    profiles = []
    for ifname, profile_data in data.items():
        try:
           profile = validate_interface_profile_data(CONFIG_DIR, ifname, profile_data)
           profiles.append((ifname, profile))
        except ValueError as error:
            print(colors("error", f"Invalid profile for '{ifname}' in {config_file_path}:\n{error}"))
            sys.exit(1)
            
    return profiles

def create_profile(CONFIG_DIR, config_file_path, ifname: str, profile_data: Dict[str, Any]) -> bool:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    print(colors("trying", f"Creating config files for {ifname}..."))

    data = {}
    if config_file_path.exists():
       try:
          with config_file_path.open("r", encoding="utf-8") as file:
               data = json.load(file)
       except (json.JSONDecodeError, IOError) as error:
          print(colors("warning", f"Could not read existing config file {config_file_path}: {error}. A new one will be created."))
       except Exception as error:
          print(colors("error", f"Could not read existing config file {config_file_path}: {error}."))
          return False

    wpa_supplicant_conf = f"""
ctrl_interface=/var/run/wpa_supplicant
network={{
    ssid="{profile_data['ssid']}"
    psk={profile_data['psk_hex']}
}}
"""
    pathlib.Path(profile_data['wpa_supplicant_conf_path']).write_text(wpa_supplicant_conf.strip() + "\n")

    dhcpcd_conf = f"""
interface {ifname}
metric {profile_data['metric']}
"""
    pathlib.Path(profile_data['dhcpcd_conf_path']).write_text(dhcpcd_conf.strip() + "\n")

    data[ifname] = profile_data

    with config_file_path.open("w", encoding="utf-8") as file:
         json.dump(data, file, indent=2, ensure_ascii=False)

    print(colors("ok", f"Profile for '{ifname}' created/updated successfully!"))
    return True

WPA_PROCESSES: dict[str, subprocess.Popen] = {}
NETWORK_SERVICES = ["wpa_supplicant", "dhcpcd"]

def _kill_all_network_services():
    print(colors("trying", f"Stopping existing network services: {NETWORK_SERVICES}"))
    for service in NETWORK_SERVICES:
        subprocess.run(["pkill", "-9", service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _stop_wpa_proc(ifname: str):
    proc = WPA_PROCESSES.pop(ifname, None)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(colors("ok", f"wpa_supplicant process for {ifname} stopped."))

def _check_wpa_cli_status(ifname: str) -> bool:
    try:
        result = subprocess.run(
           ["wpa_cli", "-i", ifname, "status"],
           capture_output=True, text=True, timeout=5
        )
        return "wpa_state=COMPLETED" in result.stdout
    except Exception:
        return False

def _start_wpa_supplicant(ifname: str, profile_data: dict) -> bool:
    _stop_wpa_proc(ifname)

    socket_path = pathlib.Path(f"/var/run/wpa_supplicant/{ifname}")
    if socket_path.exists():
        try:
            os.remove(socket_path)
        except OSError as e:
            print(colors("error", f"Could not remove old socket file {socket_path}: {e}"))
            
    try:
        print(colors("trying", f"Starting wpa_supplicant for {ifname} (SSID: {profile_data['ssid']})"))
        proc = subprocess.Popen(
          ["wpa_supplicant", "-i", ifname, "-c", profile_data["wpa_supplicant_conf_path"], "-D", "nl80211"],
          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        WPA_PROCESSES[ifname] = proc
    except Exception as e:
        print(colors("error", f"Failed to start wpa_supplicant for {ifname}: {e}"))
        return False
    
    for _ in range(20):
        if _check_wpa_cli_status(ifname):
           print(colors("ok", f"wpa_supplicant connected on {ifname}."))
           return True
        time.sleep(1)
        
    print(colors("error", f"Timeout waiting for wpa_supplicant connection on {ifname}."))
    _stop_wpa_proc(ifname)
    return False

def _start_dhcpcd(ifname: str, profile_data: dict) -> bool:
    try:
       print(colors("trying", f"Requesting IP address for {ifname}..."))
       subprocess.run(
         ["dhcpcd", "-1", ifname, "-f", profile_data["dhcpcd_conf_path"]],
         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True
       )
       print(colors("ok", f"IP address acquired for {ifname}."))
       return True
    except subprocess.CalledProcessError as error:
       print(colors("error", f"DHCP failed for {ifname}: {error.stderr.decode().strip()}"))
       return False
    except Exception as error:
       print(colors("error", f"An unexpected error occurred during DHCP for {ifname}: {error}"))
       return False

def connection(profile: Tuple[str, Dict[str, Any]]) -> bool:
    ifname, profile_data = profile
    if _start_wpa_supplicant(ifname, profile_data):
       if _start_dhcpcd(ifname, profile_data):
          print(colors("ok", f"Connection successful on {ifname}!"))
          return True
    
    print(colors("error", f"Connection failed on {ifname}."))
    return False

def start(profiles: List[Tuple[str, Dict[str, Any]]], background: bool):
    if not profiles:
       print(colors("error", "No valid profiles found."))
       return

    profiles.sort(key=lambda p: p[1]["metric"])
    _kill_all_network_services()

    if not background:
       ifname, profile_data = profiles[0]
       set_interface_down(ifname)
       set_interface_up(ifname)
       if connection((ifname, profile_data)):
          print(colors("ok", "Connection established. The script will now exit."))
          return
       print(colors("error", "Could not establish a connection using any available profile."))
       return

    print(colors("warning", "Monitoring mode activated (Ctrl+C to exit)"))
    active_ifname = None

    try:
       while True:
          best_candidate_ifname = None

          for ifname, profile_data in profiles:
              if not check_interface_exists(ifname):
                 continue

              if best_candidate_ifname is None:
                 best_candidate_ifname = ifname

          if best_candidate_ifname != active_ifname:
             if active_ifname and check_interface_exists(active_ifname):
                print(colors("trying", f"Switching from '{active_ifname}' to a better interface..."))
                set_interface_down(active_ifname)
                _stop_wpa_proc(active_ifname)

             if best_candidate_ifname:
                print(colors("ok", f"New target interface is '{best_candidate_ifname}'. Attempting to connect."))
                active_ifname = best_candidate_ifname
                current_profile = next(p for i, p in profiles if i == active_ifname)
                set_interface_up(active_ifname)
                connection((active_ifname, current_profile))
             else:
                 active_ifname = None

          elif active_ifname:
             if not check_interface_ipv4(active_ifname):
                print(colors("warning", f"Connection on '{active_ifname}' seems down (no IP). Reconnecting..."))
                current_profile = next(p for i, p in profiles if i == active_ifname)
                connection((active_ifname, current_profile))

          time.sleep(5)

    except KeyboardInterrupt:
       print(colors("ok", "\nMonitoring stopped by user."))
    except Exception as error:
       print(colors("error", f"\nMonitoring stopped by Error: {error}"))
    finally:
       if active_ifname:
          set_interface_down(active_ifname)
       _kill_all_network_services()
       print(colors("ok", "Cleaned up all connections."))

def scan(ifname: str):
    print("Scan function is under development.")
    pass

def main():
    SudoAuthentication()

    real_user = os.environ.get("SUDO_USER") or os.getlogin()
    pw = pwd.getpwnam(real_user)
    home_dir = pathlib.Path(pw.pw_dir)
    CONFIG_DIR = home_dir / ".config" / "WNPM"
    config_file_path = CONFIG_DIR / "wnpm-config.json"

    parser = argparse.ArgumentParser(description="A Python script to manage network connections.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    create_parser = subparsers.add_parser("create-profile", help="Create or update a network profile.")
    
    start_parser = subparsers.add_parser("start", help="Connect to a network.")
    start_parser.add_argument("-b", "--background", action="store_true", help="Run in monitoring mode with failover and failback.")

    scan_parser = subparsers.add_parser("scan", help="Scan for wireless networks.")
    scan_parser.add_argument("-i", "--ifname", required=True, help="The wireless interface to use for scanning.")

    args = parser.parse_args()

    if args.command == "start":
       profiles = parse_config(CONFIG_DIR, config_file_path)
       start(profiles, args.background)
    elif args.command == "scan":
       scan(args.ifname)
    elif args.command == "create-profile":
       try:
          ifname = input("Wireless Interface (e.g., wlan0): ").strip()
          if not ifname: raise ValueError("Interface name cannot be empty.")
          
          metric_val = input("Metric (default: 100): ").strip()
          metric = int(metric_val) if metric_val else 100
          
          ssid = input("Network SSID: ").strip()
          if not ssid: raise ValueError("SSID cannot be empty.")

          psk = getpass.getpass("Network Password (8-63 chars): ")
          if not psk: raise ValueError("Password cannot be empty.")

          temp_profile = {"metric": metric, "ssid": ssid, "psk": psk}
          
          valid_profile = validate_interface_profile_data(CONFIG_DIR, ifname, temp_profile)
          create_profile(CONFIG_DIR, config_file_path, ifname, valid_profile)
       except (ValueError, KeyboardInterrupt) as error:
          print(colors("error", f"\nProfile creation cancelled. Error: {error}"))
          sys.exit(1)

if __name__ == "__main__":
   main()

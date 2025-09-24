#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import json
import pathlib
import getpass
import pwd
import argparse
import hashlib
import signal
import logging
from typing import Dict, List, Any, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def PrivilegiesVerify() -> bool:
    return os.getuid() == 0

def SudoAuthentication():
    if not PrivilegiesVerify():
        print(f"This program requires administrator privileges! Run with sudo:\nsudo {sys.executable} {pathlib.Path(__file__).resolve()} {' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''}")
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
       return check_active_interface(ifname) and "inet " in result.stdout
    except Exception:
       return False

def set_interface_down(ifname: str) -> bool:
    logger.info(f"Bringing interface {ifname} down...")
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "flush", "dev", ifname], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"Interface {ifname} is down.")
        return True
    except subprocess.CalledProcessError as error:
        logger.error(f"Failed to set interface {ifname} down: {error}")
        return False

def set_interface_up(ifname: str) -> bool:
    logger.info(f"Bringing interface {ifname} up...")
    try:
       subprocess.run(["ip", "link", "set", ifname, "up"], check=True, 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       logger.info(f"Interface {ifname} is up.")
       return True
    except subprocess.CalledProcessError as error:
       logger.error(f"Failed to set interface {ifname} up: {error}")
       return False

def restart_interface(ifname: str) -> bool:
    try:
        return True if (set_interface_down(ifname) and set_interface_up(ifname)) else False
    except Exception as error:
        print(f"Error when trying to restart interface {ifname}")
        return False

def get_mac_address(ifname: str) -> str:
    try:
        path = pathlib.Path(f"/sys/class/net/{ifname}/address")
        return path.read_text().strip()
    except Exception:
        raise ValueError(f"Could not read MAC address for {ifname}")

def check_internet_connection(ifname: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-I", ifname, "-c", str(3), "-W", str(5), "8.8.8.8"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
        )
        return True
    except Exception:
        return False

def _generate_hex_psk(ssid: str, psk: str) -> str:
    return hashlib.pbkdf2_hmac('sha1', psk.encode('utf-8'), ssid.encode('utf-8'), 4096, 32).hex()

def validate_interface_profile_data(CONFIG_DIR, ifname: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    logger.info(f"Validating profile for {ifname}...")

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

    wpa_supplicant_conf_path = CONFIG_DIR / f"wpa-supplicant-{ifname}.conf"
    dhcpcd_conf_path = CONFIG_DIR / f"dhcpcd-{ifname}.conf"

    return {
      "hwaddr": hwaddr,
      "metric": metric,
      "ssid": ssid,
      "psk": psk,
      "psk_hex": psk_hex,
      "wpa_supplicant_conf_path": str(wpa_supplicant_conf_path),
      "dhcpcd_conf_path": str(dhcpcd_conf_path),
    }

def parse_config(CONFIG_DIR, config_file_path: pathlib.Path) -> List[Tuple[str, Dict[str, Any]]]:
    logger.info(f"Parsing config file {config_file_path}...")

    if not config_file_path or not config_file_path.is_file():
        logger.error(f"Configuration file not found at {config_file_path}")
        sys.exit(1)
    try:
        with config_file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as error:
        logger.error(f"Error reading JSON config: {error}")
        sys.exit(1)

    profiles = []
    for ifname, profile_data in data.items():
         try:
             valid_profile = validate_interface_profile_data(CONFIG_DIR, ifname, profile_data)
             profiles.append((ifname, valid_profile))
         except Exception as error:
             logger.error(f"Unexpected error adding profile of '{ifname}' in profiles list:\n{error}")
             sys.exit(1)
            
    return profiles

class ProfilesManager:
    def __init__(self, CONFIG_DIR: pathlib.Path, config_file_path: pathlib.Path):
        self.config_dir = CONFIG_DIR
        self.config_file_path = config_file_path

    def _read_profiles(self) -> Dict[str, Any]:
        if not self.config_file_path.exists():
            return {}
        try:
            with self.config_file_path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, IOError) as error:
            logging.warning(f"Could not read {self.config_file_path}: {error}. A new file will be created.")
            return {}
        except Exception as error:
            logging.error(f"Could not read {self.config_file_path}: {error}.")
            raise

    def _write_profiles(self, data: Dict[str, Any]):
        try:
            with self.config_file_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, ensure_ascii=False)
            self.config_file_path.chmod(0o740)
        except Exception as error:
            logging.error(f"Failed to write to {self.config_file_path}: {error}.")
            raise

    def create_profile(self, ifname: str, valid_profile: Dict[str, Any]) -> bool:
        logging.info(f"Attempting to create profile for {ifname}...")

        wpa_supplicant_conf_path = pathlib.Path(valid_profile['wpa_supplicant_conf_path'])
        wpa_supplicant_conf = f"ctrl_interface=/var/run/wpa_supplicant\nnetwork={{\n    ssid=\"{valid_profile['ssid']}\"\n    psk={valid_profile['psk_hex']}\n}}"
        wpa_supplicant_conf_path.write_text(wpa_supplicant_conf.strip() + "\n")
        wpa_supplicant_conf_path.chmod(0o740)

        dhcpcd_conf_path = pathlib.Path(valid_profile['dhcpcd_conf_path'])
        dhcpcd_conf = f"interface {ifname}\nmetric {valid_profile['metric']}"
        dhcpcd_conf_path.write_text(dhcpcd_conf.strip() + "\n")
        dhcpcd_conf_path.chmod(0o740)

        all_profiles = self._read_profiles()
        all_profiles[ifname] = {
          "metric": valid_profile["metric"],
          "ssid": valid_profile["ssid"],
          "psk": valid_profile["psk"],
        }
        self._write_profiles(all_profiles)

        logging.info(f"Profile for '{ifname}' created/updated successfully!")
        return True

    def list_profiles(self):
        data = self._read_profiles()
        if not data:
            logging.info("No network profiles found.")
            return

        logging.info("Existing network profiles:")
        for ifname, profile in data.items():
            ssid = profile.get('ssid', 'N/A')
            metric = profile.get('metric', 'N/A')
            psk = profile.get('psk', 'N/A')
            logging.info(f"Interface: {ifname}, SSID: {ssid}, Metric: {metric}, PSK: {psk}")

    def remove_profile(self, ifname: str) -> bool:
        all_profiles = self._read_profiles()
        if ifname not in all_profiles:
            logging.error(f"Profile for '{ifname}' not found.")
            return False
        
        try:
            profile_to_remove = all_profiles[ifname]
            valid_profile = validate_interface_profile_data(self.config_dir, ifname, profile_to_remove)
            
            pathlib.Path(valid_profile['wpa_supplicant_conf_path']).unlink(missing_ok=True)
            pathlib.Path(valid_profile['dhcpcd_conf_path']).unlink(missing_ok=True)
            logging.info(f"Cleaned up config files for '{ifname}'.")

        except ValueError as error:
            logging.warning(f"Could not get associated file paths for '{ifname}', but proceeding with removal from main config: {error}")
        except Exception as error:
            logging.error(f"An error occurred during file cleanup for '{ifname}': {error}")
            return False

        del all_profiles[ifname]
        self._write_profiles(all_profiles)
        
        logging.info(f"Profile for '{ifname}' removed successfully!")
        return True

    def remove_all_profiles(self) -> bool:
        if not self.config_file_path.exists():
            logging.info("No profiles to remove.")
            return True

        try:
            profiles_to_delete = parse_config(self.config_dir, self.config_file_path)
            
            for ifname, profile_data in profiles_to_delete:
                pathlib.Path(profile_data['wpa_supplicant_conf_path']).unlink(missing_ok=True)
                pathlib.Path(profile_data['dhcpcd_conf_path']).unlink(missing_ok=True)
                logging.info(f"Removed config files for '{ifname}'.")

            self.config_file_path.unlink()
            logging.info("All network profiles have been removed.")
            return True
        except SystemExit:
            logging.info("Failed to parse config file for cleanup. Doing Manual cleanup...")
            if self.config_dir.exists():
                shutil.rmtree(self.config_dir)
            return True
        except Exception as error:
            logging.error("Failed to parse config file for cleanup. Manual cleanup may be required.")
            return False

class WPAProcessManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
    
    def start(self, ifname: str, config_path: str) -> bool:
        self.stop(ifname)
        
        socket_path = pathlib.Path(f"/var/run/wpa_supplicant/{ifname}")
        if socket_path.exists():
            try:
                os.remove(socket_path)
            except OSError as e:
                logger.error(f"Could not remove old socket file {socket_path}: {e}")
                
        try:
            logger.info(f"Starting wpa_supplicant for {ifname}")
            proc = subprocess.Popen(
                ["wpa_supplicant", "-i", ifname, "-c", config_path, "-D", "nl80211"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes[ifname] = proc
            return True
        except Exception as e:
            logger.error(f"Failed to start wpa_supplicant for {ifname}: {e}")
            return False

    def stop(self, ifname: str):
        proc = self.processes.pop(ifname, None)
        if proc and proc.poll() is None:
            logger.info(f"Stopping wpa_supplicant for {ifname}")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            logger.info(f"wpa_supplicant process for {ifname} stopped.")
    
    def stop_all(self):
        for ifname, proc in list(self.processes.items()):
            self.stop(ifname)

wpa_manager = WPAProcessManager()

def cleanup_network_processes():
    logger.info("Cleaning up network processes")
    wpa_manager.stop_all()
    
    subprocess.run(["pkill", "-9", "wpa_supplicant"], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    subprocess.run(["pkill", "-9", "dhcpcd"], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
    if not wpa_manager.start(ifname, profile_data["wpa_supplicant_conf_path"]):
        return False
    
    for _ in range(20):
        if _check_wpa_cli_status(ifname):
           logger.info(f"wpa_supplicant connected on {ifname}.")
           return True
        time.sleep(1)
        
    logger.error(f"Timeout waiting for wpa_supplicant connection on {ifname}.")
    wpa_manager.stop(ifname)
    #cleanup_network_processes()
    return False

def _start_dhcpcd(ifname: str, profile_data: dict) -> bool:
    try:
       logger.info(f"Requesting IP address for {ifname}...")
       subprocess.run(
         ["dhcpcd", "-n", "-1", ifname, "-f", profile_data["dhcpcd_conf_path"]],
         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True
       )
       logger.info(f"IP address acquired for {ifname}.")
       return True
    except subprocess.CalledProcessError as error:
       logger.error(f"DHCP failed for {ifname}: {error.stderr.decode().strip()}")
       return False
    except Exception as error:
       logger.error(f"An unexpected error occurred during DHCP for {ifname}: {error}")
       return False

def connection(profile: Tuple[str, Dict[str, Any]]) -> bool:
    ifname, profile_data = profile
    restart_interface(ifname)
    if _start_wpa_supplicant(ifname, profile_data):
        if _start_dhcpcd(ifname, profile_data):
           if check_internet_connection(ifname):
              logger.info(f"Connection successful on {ifname}!")
              return True
    
    logger.error(f"Connection failed on {ifname}.")
    return False

def start(profiles: List[Tuple[str, Dict[str, Any]]], background: bool, sleep_time: int):
    if not profiles:
        logger.error("No valid profiles found.")
        return

    profiles.sort(key=lambda p: p[1]["metric"])
    cleanup_network_processes()

    if not background:
       ifname, profile_data = profiles[0]
       restart_interface(ifname)
       if connection((ifname, profile_data)):
          logger.info("Connection established. The script will now exit.")
          return
       logger.error("Could not establish a connection using any available profile.")
       return

    logger.info("Monitoring mode activated (Ctrl+C to exit)")

    active_ifname = None

    try:
        while True:
            """
            best_candidate_ifname = None
            for ifname, profile_data in profiles:
                if not check_interface_exists(ifname):
                    continue

                if best_candidate_ifname is None:
                    best_candidate_ifname = ifname
            """
            best_candidate_ifname = next((ifname for ifname, _ in profiles if check_interface_exists(ifname)), None)
            if best_candidate_ifname != active_ifname:
                if active_ifname and check_interface_exists(active_ifname):
                    logger.info(f"Switching from '{active_ifname}' to a better interface...")
                    restart_interface(active_ifname)
                    wpa_manager.stop(active_ifname)

                if best_candidate_ifname:
                    logger.info(f"New target interface is '{best_candidate_ifname}'. Attempting to connect.")
                    active_ifname = best_candidate_ifname
                    current_profile = next(p for i, p in profiles if i == active_ifname)
                    connection((active_ifname, current_profile))
                else:
                    active_ifname = None

            elif active_ifname:
                if not (check_interface_ipv4(active_ifname) or check_internet_connection(active_ifname)):
                    logger.warning(f"Connection on '{active_ifname}' seems down (no IP). Reconnecting...")
                    current_profile = next(p for i, p in profiles if i == active_ifname)
                    connection((active_ifname, current_profile))

            time.sleep(sleep_time)

    except KeyboardInterrupt:
       logger.info("\nMonitoring stopped by user.")
    except Exception as error:
       logger.error(f"\nMonitoring stopped by Error: {error}")
    finally:
       cleanup_network_processes()
       logger.info("Cleaned up all connections.")

def scan(ifname: str):
    print("Scan function is under development.")
    pass

def main():
    SudoAuthentication()

    real_user = os.environ.get("SUDO_USER") or os.getlogin()
    pw = pwd.getpwnam(real_user)
    home_dir = pathlib.Path(pw.pw_dir)
    CONFIG_DIR = home_dir / ".config" / "WNPM"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.chmod(0o740)
    config_file_path = CONFIG_DIR / "wnpm-config.json"
    profiles_manager = ProfilesManager(CONFIG_DIR, config_file_path)

    parser = argparse.ArgumentParser(description="A Python script to manage network connections.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    create_profiles_parser = subparsers.add_parser("create-profile", help="Create or update a network profile.")

    list_profiles_parser = subparsers.add_parser('list-profiles', help='List all saved network profiles.')

    remove_profiles_parser = subparsers.add_parser('remove-profile', help='Remove a specific network profile.')
    remove_profiles_parser.add_argument('ifname', type=str, help='The interface name to remove.')

    remove_all_profiles_parser = subparsers.add_parser('remove-profiles', help='Remove all network profiles.')

    start_parser = subparsers.add_parser("start", help="Connect to a network.")
    start_parser.add_argument("-b", "--background", action="store_true", help="Run in monitoring mode with failover and failback.")
    start_parser.add_argument("-s", "--sleep", type=int, default=6, help="Time to next interface check (seconds, default = 6)")

    scan_parser = subparsers.add_parser("scan", help="Scan for wireless networks.")
    scan_parser.add_argument("-i", "--ifname", required=True, help="The wireless interface to use for scanning.")

    args = parser.parse_args()

    if args.command == "start":
       profiles = parse_config(CONFIG_DIR, config_file_path)
       start(profiles, args.background, args.sleep)
    elif args.command == "scan":
       scan(args.ifname)
    elif args.command == "create-profile":
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
        profiles_manager.create_profile(ifname, valid_profile)
    elif args.command == 'list-profiles':
        profiles_manager.list_profiles()
    elif args.command == 'remove-profile':
        profiles_manager.remove_profile(args.ifname)
    elif args.command == 'remove-profiles':
        profiles_manager.remove_all_profiles()
    else:
        parser.print_help()
    

if __name__ == "__main__":
   main()

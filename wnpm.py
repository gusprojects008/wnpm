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
import signal
import logging
from typing import Dict, List, Any, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def PrivilegiesVerify() -> bool:
    return os.getuid() == 0

def SudoAuthentication():
    if not PrivilegiesVerify():
        print("\nThis program requires administrator privileges!\n")
        try:
           subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
           sys.exit(0)
        except subprocess.CalledProcessError:
            print("Failed to obtain sudo privileges.")
            sys.exit(1)
        except Exception as error:
            print(f"Unexpected error: {error}")
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

def get_mac_address(ifname: str) -> str:
    try:
        path = pathlib.Path(f"/sys/class/net/{ifname}/address")
        return path.read_text().strip()
    except Exception:
        raise ValueError(f"Could not read MAC address for {ifname}")

def _generate_hex_psk(ssid: str, psk: str) -> str:
    return hashlib.pbkdf2_hmac('sha1', psk.encode('utf-8'), 
                              ssid.encode('utf-8'), 4096, 32).hex()

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

    wpa_supplicant_conf_path = CONFIG_DIR / f"wpa_supplicant_{ifname}.conf"
    dhcpcd_conf_path = CONFIG_DIR / f"dhcpcd_{ifname}.conf"

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
           profile = validate_interface_profile_data(CONFIG_DIR, ifname, profile_data)
           profiles.append((ifname, profile))
        except ValueError as error:
            logger.error(f"Invalid profile for '{ifname}' in {config_file_path}:\n{error}")
            sys.exit(1)
            
    return profiles

def create_profile(CONFIG_DIR, config_file_path, ifname: str, profile_data: Dict[str, Any]) -> bool:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Creating config files for {ifname}...")

    data = {}
    if config_file_path.exists():
       try:
          with config_file_path.open("r", encoding="utf-8") as file:
               data = json.load(file)
       except (json.JSONDecodeError, IOError) as error:
          logger.warning(f"Could not read existing config file {config_file_path}: {error}. A new one will be created.")
       except Exception as error:
          logger.error(f"Could not read existing config file {config_file_path}: {error}.")
          return False

    wpa_supplicant_conf_path = pathlib.Path(profile_data['wpa_supplicant_conf_path'])
    wpa_supplicant_conf = f"""
ctrl_interface=/var/run/wpa_supplicant
network={{
    ssid="{profile_data['ssid']}"
    psk={profile_data['psk_hex']}
}}
"""
    wpa_supplicant_conf_path.write_text(wpa_supplicant_conf.strip() + "\n")
    wpa_supplicant_conf_path.chmod(0o740)

    dhcpcd_conf_path = pathlib.Path(profile_data['dhcpcd_conf_path'])
    dhcpcd_conf = f"""
interface {ifname}
metric {profile_data['metric']}
"""
    dhcpcd_conf_path.write_text(dhcpcd_conf.strip() + "\n")
    dhcpcd_conf_path.chmod(0o740)

    data[ifname] = {
        "metric": profile_data["metric"],
        "ssid": profile_data["ssid"],
        "psk": profile_data["psk"],  # Note: storing plaintext PSK - consider security implications
    }

    with config_file_path.open("w", encoding="utf-8") as file:
         json.dump(data, file, indent=2, ensure_ascii=False)

    config_file_path.chmod(0o740)

    logger.info(f"Profile for '{ifname}' created/updated successfully!")
    return True

class WPAProcessManager:
    """Gerenciador de processos wpa_supplicant"""
    
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
    
    def stop_all(self):
        """Para todos os processos gerenciados"""
        for ifname, proc in list(self.processes.items()):
            self.stop(ifname)
    
    def stop(self, ifname: str):
        """Para um processo específico"""
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
    
    def start(self, ifname: str, config_path: str) -> bool:
        """Inicia o wpa_supplicant para uma interface"""
        self.stop(ifname)  # Para qualquer instância existente
        
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

# Instância global do gerenciador de processos
wpa_manager = WPAProcessManager()

def cleanup_network_processes():
    """Limpa processos de rede residual"""
    logger.info("Cleaning up network processes")
    wpa_manager.stop_all()
    
    # Mata quaisquer processos wpa_supplicant restantes
    subprocess.run(["pkill", "-9", "wpa_supplicant"], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Para o dhcpcd service se estiver rodando
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
    return False

def _start_dhcpcd(ifname: str, profile_data: dict) -> bool:
    try:
       logger.info(f"Requesting IP address for {ifname}...")
       subprocess.run(
         ["dhcpcd", "-1", ifname, "-f", profile_data["dhcpcd_conf_path"]],
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
    if _start_wpa_supplicant(ifname, profile_data):
       if _start_dhcpcd(ifname, profile_data):
          logger.info(f"Connection successful on {ifname}!")
          return True
    
    logger.error(f"Connection failed on {ifname}.")
    return False

def start(profiles: List[Tuple[str, Dict[str, Any]]], background: bool):
    if not profiles:
       logger.error("No valid profiles found.")
       return

    profiles.sort(key=lambda p: p[1]["metric"])
    cleanup_network_processes()

    if not background:
       ifname, profile_data = profiles[0]
       set_interface_down(ifname)
       set_interface_up(ifname)
       if connection((ifname, profile_data)):
          logger.info("Connection established. The script will now exit.")
          return
       logger.error("Could not establish a connection using any available profile.")
       return

    logger.info("Monitoring mode activated (Ctrl+C to exit)")
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
                logger.info(f"Switching from '{active_ifname}' to a better interface...")
                set_interface_down(active_ifname)
                wpa_manager.stop(active_ifname)

             if best_candidate_ifname:
                logger.info(f"New target interface is '{best_candidate_ifname}'. Attempting to connect.")
                active_ifname = best_candidate_ifname
                current_profile = next(p for i, p in profiles if i == active_ifname)
                set_interface_up(active_ifname)
                connection((active_ifname, current_profile))
             else:
                 active_ifname = None

          elif active_ifname:
             if not check_interface_ipv4(active_ifname):
                logger.warning(f"Connection on '{active_ifname}' seems down (no IP). Reconnecting...")
                current_profile = next(p for i, p in profiles if i == active_ifname)
                connection((active_ifname, current_profile))

          time.sleep(5)

    except KeyboardInterrupt:
       logger.info("\nMonitoring stopped by user.")
    except Exception as error:
       logger.error(f"\nMonitoring stopped by Error: {error}")
    finally:
       if active_ifname:
          set_interface_down(active_ifname)
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
          logger.error(f"\nProfile creation cancelled. Error: {error}")
          sys.exit(1)

if __name__ == "__main__":
   main()

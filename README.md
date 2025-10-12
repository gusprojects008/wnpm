# Network Interface Profile Manager (NIPM)

NIPM (Network Interface Profile Manager) is a CLI tool for Linux that allows you to manage network interfaces and their connections (Wi-Fi or Ethernet) through profiles.
It supports the creation, maintenance, and automatic switching between network profiles dynamically and securely, without relying on a resident daemon, offering greater control and flexibility over interfaces.

---

## Overview

**NIPM** works directly with the standard Linux networking tools:

* [`dhcpcd.conf`](https://wiki.archlinux.org/title/Dhcpcd)
* [`wpa_supplicant.conf`](https://wiki.archlinux.org/title/Wpa_supplicant)

It automates the creation and updating of these configuration files, ensuring compliance with the official syntax and reducing manual errors.

NIPM prioritizes network interfaces based on user-defined metrics and automatically reconnects in case of failure, ensuring a reliable connection experience.

---

## Main Features

* **Profile creation and updating**: With the `create-profile` command, you can define the SSID, password (PSK), and priority (metric) for each interface. The lower the interface's metric, the higher its priority.
* **Centralized management**: Keeps all settings organized in the user profile directory (`~/.config/nipm`), which is only accessible with root permissions for security reasons.
* **Multiple interface support**: Dynamically switches between active interfaces, always maintaining the priority connection.
* **Continuous monitoring**: Background mode (`-b`) checks interface availability and automatically reconnects in case of failure. You can also set the time for each check using the option (`-s`) and then the value in seconds. * **Easy profile removal**: You can remove individual profiles or all profiles at once.
* **Compatibility**: Uses standard Linux tools (`dhcpcd`, `wpa_supplicant`) without complex external dependencies.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/gusprojects008/nipm.git
cd nipm
````

Make sure you have Python 3.13+, `dhcpcd`, and `wpa_supplicant` installed.

---

## Usage

```bash
# Show help
sudo python3 nipm.py --help

# Create or update a network profile
sudo python3 nipm.py create-profile

# List all saved profiles
sudo python3 nipm.py list-profiles

# Remove a specific profile
sudo python3 nipm.py remove-profile <interface>

# Remove all profiles
sudo python3 nipm.py remove-profiles

# Start connection with interface monitoring (background)
sudo python3 nipm.py start -b

# Start connection without monitoring (single mode)
sudo python3 nipm.py start
```

> During profile creation, you will be prompted for:
>
> * Interface name (e.g., `wlan0`)
> * Network SSID
> * Network password (PSK)
> * Metric (interface priority, default = 100)

---

## Configuration Structure

* User configuration directory: `~/.config/nipm/`
* Main profile file: `nipm-config.json`
* Generated configuration files for each interface:

* `wpa-supplicant-<ifname>.conf`
* `dhcpcd-<ifname>.conf`

All files and directories are created with restricted permissions (`740`) for added security.

---

## Requirements

* Python 3.13+
* `dhcpcd`
* `wpa_supplicant`
* Administrator permissions (sudo)

#### Ensure that no daemons or network services are running (e.g., iwd or NetworkManager) before running the program.

---

## Strengths

* Reliability and automation for multiple wireless or Ethernet interfaces.

* Flexibility for use in monitoring mode or single-run mode.
* Native integration with standard Linux tools, without external dependencies.
* Easy maintenance of network profiles on multi-interface systems.

---

## License

MIT License – see [LICENSE](LICENSE) for details.

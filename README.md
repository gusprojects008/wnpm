# Wireless Network Profile Manager (WNPM)

A simple command-line utility for managing network interface connections to Wi-Fi networks in a dynamic and customizable way.

---

## Overview

WNPM allows you to create and maintain profiles for your wireless connections by working directly with:

* [`dhcpcd.conf`](https://wiki.archlinux.org/title/Dhcpcd)
* [`wpa_supplicant.conf`](https://wiki.archlinux.org/title/Wpa_supplicant)

It automates editing these files while respecting their official configuration syntax.

---

## Features

* Create or update profiles using the `create-profile` command.
* Keep network configurations organized and reusable.
* Compatible with standard Linux tools (`dhcpcd`, `wpa_supplicant`).
* Set interface priority, automatic reconnection to the priority interface, which is dynamically set according to its availability.
* Customize dhcpcd and wpa_supplicant configuration files as needed, consult the documentation, and be careful when setting psk directly to the wpa_supplicant or wnpm-config.json configuration file.

---

## Installation

```bash
# Clone the repository
 git clone https://github.com/gusprojects008/WNPM.git
 cd WNPM
```

## Usage

```bash
# Show help
python wnpm.py --help

# Create or update a wireless profile
python wnpm.py create-profile <profile-name>
```

---

## Requirements

* Python 3
* dhcpcd
* wpa\_supplicant

Ensure these packages are installed on your system.

---

## License

MIT License – see [LICENSE](LICENSE) for details.

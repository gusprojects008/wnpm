# Wireless Network Profile Manager (WNPM)

A simple command‑line utility to manage **dhcpcd** and **wpa\_supplicant** configuration files for wireless network profiles.

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

---

## Installation

```bash
# Clone the repository
 git clone https://github.com/youruser/wnpm.git
 cd wnpm

# Run the setup script (creates a Python virtual environment)
 ./setup.sh
```

> Use `./setup.sh --force` to recreate the virtual environment if needed.

---

## Usage

```bash
# Activate the virtual environment
source venv/bin/activate

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

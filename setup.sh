#!/bin/bash
set -e

echo ">>> Checking required system packages..."

for pkg in python dhcpcd wpa_supplicant pkill; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo "Error: '$pkg' is not installed. Please install it before running this setup."
        exit 1
    fi
done

echo ">>> All required packages are present."

echo ">>> Creating Python virtual environment..."
python3 -m venv venvpy-netcfg

echo ">>> Activating virtual environment..."
source venvpy-netcfg/bin/activate

echo ">>> Installing Python packages from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

echo ">>> Setup completed successfully!"
echo ""
echo ">>>> If needed, you can check this script (setup.sh) for the manual commands to perform each step."
echo ">>>> Now, run: source venvpy-wnpm/bin/activate"
echo ">>>> Then: python wnpm.py --help"

#!/bin/bash

# Install Python and friends for traffic analysis
sudo dnf install -y $(cat ~/bgp_scripts/required_packages.txt)
sudo python3 -m pip install scapy

# Download traffic generator code
git clone https://github.com/pjw7904/Basic-Traffic-Generator.git

# Turn on IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

echo "DCN compute node initialization script has finished."

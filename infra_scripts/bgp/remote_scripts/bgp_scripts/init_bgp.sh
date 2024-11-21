#!/bin/bash

# frr-stable will be the latest official stable release. This can be changed if you're looking for a specific version of FRR.
FRRVER="frr-stable"

# Add RPM repository. This was built for Red Hed 8, but works with Rocky 8 as well.
#    Note: Supported since FRR 7.3
curl -O https://rpm.frrouting.org/repo/$FRRVER-repo-1-0.el8.noarch.rpm
sudo yum install -y ./$FRRVER*

# install FRR.
sudo yum install -y frr frr-pythontools

# Give permissions to user to access frr files (this requires a logout after to take effect)
sudo usermod -a -G frr,frrvty $(logname)

# Install Python and friends for traffic analysis
sudo dnf install -y $(cat ~/bgp_scripts/required_packages.txt)
sudo python3 -m pip install scapy psutil

# Turn on IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# A "here" document to get around the logout/login requirements of adding a group to a user
newgrp frr << END
sudo sed -i 's/bgpd=no/bgpd=yes/g' /etc/frr/daemons
sudo sed -i 's/bfdd=no/bfdd=yes/g' /etc/frr/daemons
sudo sed -i 's/#frr_profile="datacenter"/frr_profile="datacenter"/g' /etc/frr/daemons
sudo mv bgp_scripts/frr.conf /etc/frr/frr.conf
sudo service frr start
END

echo "BGP-DCN initialization script has finished."

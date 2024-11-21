#!/bin/bash

# Function to execute when SIGHUP is caught. In our tests, this means the tmux session has been killed and SIGHUP is sent to the script.
cleanup() {
    # Kill the shark
    sudo pkill -SIGINT tshark
    
    # Read the file and filter out only the BGP UPDATE messages.
    createPcap "/home/rocky/bgp_scripts/bgp_update_only.pcap"
    
    # Create a pcap containing only BGP UPDATE messages from the pcap containing all BGP messages.
    sudo tshark -r bgp_all_messages.pcap -Y "bgp.type == 2" -w bgp_update_only.pcap
    
    # Run the analysis script on the UPDATE file
    sudo python3 BGPOverheadCalculator.py
}

# Function to determine if the provided FILE_PATH pcap exists yet, and create it if not.
createPcap() {
    local FILE_PATH=$1
    
    # Check if file FILE_PATH exists yet
    if [ ! -f "$FILE_PATH" ]; then
        # File does not exist, so create it
        sudo touch "$FILE_PATH"

        # Change permissions of the file
        sudo chmod 777 "$FILE_PATH"
    fi
}

# Set a trap for the SIGHUP signal and call the cleanup function.
trap cleanup SIGHUP

# If an interface is to be excluded for traffic analysis, mark that interface.
excludedInterface="none"
if [ ! -z "$1" ]; then
    excludedInterface="$1"
fi

# Find all available interfaces that start with "eth" but are NOT eth0 (management interface) or the inputted excluded interface.
ALL_INTERFACES=$(ip link show | awk -F: -v excl="$excludedInterface" '$2 ~ /^ eth/ && $2 !~ /eth0/ && ($2 !~ excl || excl == "none") {gsub(/ /, "", $2); print $2}')

# Build the included interface list.
INCLUDED_INTFS=""
for iface in $ALL_INTERFACES; do
        INCLUDED_INTFS="$INCLUDED_INTFS -i $iface"
done

# Create the pcap file if it hasn't already been created yet.
createPcap "/home/rocky/bgp_scripts/bgp_all_messages.pcap"

# Run tshark with the included interfaces, filter out TCP port 179 (BGP), and save it to the pcap.
sudo tshark -f "port 179"  $INCLUDED_INTFS -w bgp_all_messages.pcap &
wait
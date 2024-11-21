#!/bin/bash

# Clear the FRR BGP log file
sudo chmod +r /var/log/frr/bgpd.log
sudo truncate -s 0 /var/log/frr/bgpd.log

# Remove all pcap files
sudo rm ~/bgp_scripts/*.pcap

# Remove additional log files
sudo rm ~/bgp_scripts/*.log

# Kill the prior session if it is still there for some reason
tmux has-session -t bgp 2>/dev/null
if [ $? == 0 ]; then
  tmux kill-session -t bgp
fi

# If an interface is to be excluded for traffic analysis, mark that interface.
excludedInterface=""
if [ ! -z "$1" ]; then
    excludedInterface="$1"
fi

# Start collecting BGP messages and parse them when the experiment concludes.
if [ ! -z "$excludedInterface" ]; then
    tmux new-session -d -s bgp "cd ~/bgp_scripts && bash bgp_capture_update_messages.sh '$excludedInterface'"
else
    tmux new-session -d -s bgp "cd ~/bgp_scripts && bash bgp_capture_update_messages.sh"
fi

echo "Script has finished"
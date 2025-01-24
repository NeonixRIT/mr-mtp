echo '127.0.0.1 H-1' | sudo tee -a /etc/hosts
sudo apt update
sudo apt upgrade -y
sudo apt-get install -y $(cat ~/bgp_scripts/required_packages_debian.txt)
sudo apt install -y python3.11 python3-pip tshark tmux git frr frr-pythontools python3-scapy neovim
sudo usermod -a -G frr,frrvty $(logname)
sudo sysctl -w net.ipv4.ip_forward=1

newgrp frr << END
sudo sed -i 's/bgpd=no/bgpd=yes/g' /etc/frr/daemons
sudo sed -i 's/bfdd=no/bfdd=yes/g' /etc/frr/daemons
sudo sed -i 's/#frr_profile="datacenter"/frr_profile="datacenter"/g' /etc/frr/daemonsf
sudo service frr enable
END




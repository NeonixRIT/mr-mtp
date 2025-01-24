mkdir ~/captures
cd ~/captures
touch $1
sudo chmod 777 $1
sudo tcpdump -i any -w $1
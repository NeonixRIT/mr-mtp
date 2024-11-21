sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64510
neighbor 192.168.0.254 remote-as 64512
neighbor 192.168.0.254 no bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64512
neighbor 192.168.0.1 remote-as 64510
neighbor 192.168.0.1 no bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
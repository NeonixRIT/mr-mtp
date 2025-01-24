sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64515
neighbor 172.16.2.1 remote-as 64512
no neighbor 172.16.2.1 bfd
neighbor 172.16.6.1 remote-as 64512
no neighbor 172.16.6.1 bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
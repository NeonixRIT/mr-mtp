sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64516
neighbor 172.16.3.1 remote-as 64512
no neighbor 172.16.3.1 bfd
neighbor 172.16.7.1 remote-as 64512
no neighbor 172.16.7.1 bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
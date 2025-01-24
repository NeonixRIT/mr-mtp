sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64512
neighbor 172.16.4.2 remote-as 64513
no neighbor 172.16.4.2 bfd
neighbor 172.16.5.2 remote-as 64514
no neighbor 172.16.5.2 bfd
neighbor 172.16.6.2 remote-as 64515
no neighbor 172.16.6.2 bfd
neighbor 172.16.7.2 remote-as 64516
no neighbor 172.16.7.2 bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64512
neighbor 192.168.0.1 remote-as 64510
no neighbor 192.168.0.1 bfd
neighbor 172.16.0.2 remote-as 64513
no neighbor 172.16.0.2 bfd
neighbor 172.16.1.2 remote-as 64514
no neighbor 172.16.1.2 bfd
neighbor 172.16.2.2 remote-as 64515
no neighbor 172.16.2.2 bfd
neighbor 172.16.3.2 remote-as 64516
no neighbor 172.16.3.2 bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
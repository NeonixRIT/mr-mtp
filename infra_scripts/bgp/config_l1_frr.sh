sudo systemctl restart frr
sudo vtysh << END
conf t
router bgp 64513
neighbor 172.16.0.1 remote-as 64512
no neighbor 172.16.0.1 bfd
neighbor 172.16.4.1 remote-as 64512
no neighbor 172.16.4.1 bfd
timers bgp 5 15
exit
exit
show ip bgp summary
exit
END
log file /var/log/frr/bgpd.log
log timestamp precision 3
!
debug bgp updates in
debug bgp updates out
debug bgp updates detail
!
bfd
 profile lowerIntervals
  transmit-interval 100
 !
% for neighbor in neighbors:
 peer ${neighbor["ip"]}
  profile lowerIntervals
  no shutdown
% endfor
!
exit
!
router bgp ${bgp_asn}
 timers bgp 1 3
% for neighbor in neighbors:
 neighbor ${neighbor["ip"]} remote-as ${neighbor["asn"]}
 neighbor ${neighbor["ip"]} bfd
% endfor
 !
% if networks:
 address-family ipv4 unicast
% for network in networks:
  network ${network}
% endfor
 exit-address-family
% endif
exit
'''
Analyze BGP packet captures (pcap) and determine the overhead resulting from those messages.
Author: Peter Willis (pjw7904@rit.edu)
'''
from scapy.all import *
from scapy.contrib.bgp import * # Need a specific import for BGP-related classes and headers
import psutil # Gaining access to interfaces and IPv4 addressing
import socket # Address families

def getIPv4Addresses():
    addressList = [] # Store the IPv4 addresses

    # Get all network interfaces (along with their addresses)
    interfaces = psutil.net_if_addrs()

    # Iterate through each interface and their associated IPv4 address and add it to the address list.
    for interfaceName, interfaceAddresses in interfaces.items():
        for address in interfaceAddresses:
            if address.family == socket.AF_INET:  # Check for IPv4 addresses only, not IPv6 or other types.
                addressList.append(address.address)
                
    return addressList

# Initialize values
BGPConf.use_2_bytes_asn = False # Set 4-byte ASN field, as that is what the FRR implementation uses.

UPDATE_HEADER = "BGPUpdate" # Look specifically for the BGP UPDATE header within the packets.
IP_HEADER = "IP" # IPv4 header name.

# Overhead calcuations
packetOverhead = 0 # The total length of any layer 3+ data sent (i.e., the total length of the IP + TCP + BGP headers) in octets.
withdrawOverhead = 0 # The total length of the Withdrawn Routes field in octets. A subset of packetOverhead.
additionOverhead = 0 # The total length of the Path Attributes field in octets. A subset of packetOverhead.

# Get the local IPv4 addressing.
addresses = getIPv4Addresses()

# Read the capture file and load the frames into the packets structure
packets = rdpcap("bgp_update_only.pcap")

# Iterate through the frames
for packet in packets:
	# For each packet received (i.e., not sent, only received) that has the BGP UPDATE header
    if(packet.haslayer(UPDATE_HEADER) and packet[IP_HEADER].src not in addresses):
        packetOverhead += packet[IP_HEADER].len

        if(packet[UPDATE_HEADER].withdrawn_routes_len > 0):
            withdrawOverhead += packet[UPDATE_HEADER].withdrawn_routes_len
        if(packet[UPDATE_HEADER].path_attr_len > 0):
            additionOverhead += packet[UPDATE_HEADER].path_attr_len

# Write overhead to file
with open("overhead.log", "w") as logFile:
    logFile.write(f"IPv4 Packet Overhead:{packetOverhead}\n")
    logFile.write(f"BGP Withdrawn Routes Overhead:{withdrawOverhead}\n")
    logFile.write(f"BGP Added Routes Overhead:{additionOverhead}")
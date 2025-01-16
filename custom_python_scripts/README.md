# Problem
The testing environment had a small Data Center Network topology, with rocky linux nodes acting as routers running an instance of the Border Gateway Protocol (BGP) through FRRouting (FRR). In order to demonstrate the vulnerabilities of BGP, another node was attached to this network to act as a compromised BGP peer.

Initially, this BGP peer, running Kali Linux, interacted with the DCN using its own instance of FRR. This, however, was shown to be in adiquate. This is because, in order to demonstrate BGPs vulnerabilities, such as route hijacking, the compromised BGP peer needs to craft and send a BGP UPDATE message with specific data. FRR was not made for this level of granularity, so using FRR to craft such messages was out of the question.

# The Next Step
Since FRR wasn't itself enough, other software had to be brought into the picture. Scapy is a powerful Python library that provides the ability to capture, craft, and send packets and provides data structures for common protocols.

So, with FRR running and having an established BGP peer session with a peer in the DCN, scapy can be used to craft the appropriate UPDATE packet to inject into that session.

# Issues with scapy
Unfortunately, scapy's implementation of BGP, to craft BGP messages, is rather convoluted and hardly documented making it difficult to create the appropriate fields and setting the correct values, so that, when converted to bytes, would be recognized by the BGP peer as a valid message. This being demonstrated with the BGP peer responding with a notification (error) message in response to recieving BGP messages crafted in this way. So, while scapy's BGP implementation was not reliable to use, scapy can still be used, at this point, to capture and inject packets into the FRR BGP session. To ensure that this is the case, scapy can be provided raw bytes to send. 

However, in providing the raw bytes of a known valid BGP UPDATE message to scapy, another issue came to the surface. Scapy's injection of a packet into the TCP stream is not tracked by either end of the BGP session. The packet sends successfully, the peer recieves it and acknoledges it, but the socket sees this as an acknowledgement for data that was not sent. This seems to ultimately devolve the BGP and TCP session until it is reset (RST) and restablished some time later. While this may have some other interesting implications, these issues disqualify scapy from being used as a transport method or for packet construction. Note that scapy could still be used as a transport method, but this would almost require a full implementation of TCP.

# Problem Reevaluation
With scapy out of the question, a solution for building BGP packets easily is still needed, not to mention a way to inject UPDATE messages into a BGP session so that they have the desired affect of changing the peers routing table while keeping the session valid. A major cause of this issue, however, comes from FRR being responsible for managing the BGP peer session which is separate from the method of building and sending custom BGP messages. Evaluating FRR further, it has a lot of functionality that isn't needed for this use case, such as actually routing traffic, storing data, etc. 

This makes replacing FRR entirely a feesible solution and it just so happens Python has a built in socket library for creating TCP connections, which wasn't the first choice due to FRR already gracefully handling BGP sessions. By using Python's sockets, the method for packet construction and transport can also be unified

# BGP Sessions
BGP Sessions are rather simple to establish for the most part. First, BGP sessions can only be established with pre-configured peers. Once a TCP session is established, OPEN messages are exchange to negotiate various session parameters. Then, KEEPALIVE messages are exchange, update messages are exchanged (essentially containing all of the peers routes), and finally, exchange KEEPALIVE messages again. KEEPALIVE messages are then repeatedly sents at regular intervals based on a negotiated timer.

# Solution
With these requirements laid out, a majority of the work is creating structures to easily create BGP messages and convert those messages to bytes and parse them from bytes. The following files contain these definitions, relying heavily on object oriented programming:

`fields.py` -  Contains the most abstract versions of data structures used to build BGP packets, as well as defenitions for converting primitive types into bytes for a BGP packet
`bgp_fields.py` - Contains most fields found in various BGP messages that usually contain more complex data structures such that these fields now have meaning in the context of BGP
`bgp_messages.py` - Contains the complete structure definitions for all four BGP messages (OPEN, UPDATE, KEEPALIVE, NOTIFICATION) and how to parse bytes into these messages
`bgp_messages_test.py` - Contains examples for creating each message type and tests to ensure encoding and decoding work as intended

All thats left is creating and managing BGP sessions, which becomes trivial since most functionality doesn't need to be implemented. Simply the ability to send and recieve data as well as the ability to do a BGP handshake.

`transport.py` - Wrapper class for managing a TCP socket using python sockets
`bgp_router.py` - Uses transport wrapper to conduct a BGP handshake with another peer and establish a valid BGP session

It is now possible to establish and manage BGP peer sessions and create and send arbitrary BGP messages to peers

# Other files
`scapy_tcp_injection.py` - This file uses scapy to injecting a BGP UPDATE message into a local TCP session that is simulating an established BGP session. The same code can be used in an FRR BGP session and demonstrate the issue mentioned earlier.



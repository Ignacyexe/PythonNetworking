import os
import socket
import struct
from ctypes import *

import threading
import time
from netaddr import IPNetwork, IPAddress

host = "10.20.30.110"
subnet = "10.20.30.0/24"
# magic string, for which we are going to check ICMP responses
magic_message = b"SCANNING"


def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip, 65212))
        except:
            pass


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # mapping protocols to its names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # ip addresses readable for humans
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # protocols readable for humans
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# starting to send packets
t = threading.Thread(target=udp_sender, args=(subnet, magic_message))
t.start()

try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        # creating ip header from first 20 bytes from buffer
        ip_header = IP(raw_buffer[0:20])
        # if you want to do host discovery comment this printline
        print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")

        # decoding ICMP
        if ip_header.protocol == "ICMP":
            # reading beginning of ICMP packet
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            # creating ICMP structure
            icmp_header = ICMP(buf)
            # if you want to do only host discovery comment this printline
            print(f"ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}")

            # checking if type and code is type 3
            if icmp_header.code == 3 and icmp_header.type == 3:
                # making sure the host is in the subnet
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    # checking if there is a magic message
                    if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                        print(f"Host: {ip_header.src_address}")

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

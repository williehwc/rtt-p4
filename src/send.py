#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import string
import os

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, sniff, hexdump
from scapy.all import Ether, IP, TCP

this_ip = {"h1-eth0": "10.0.1.1", "h2-eth0": "10.0.2.2"}
destination_ips = {"h1-eth0": "10.0.2.2", "h2-eth0": "10.0.1.1"}
num_chars_per_packet = 10
min_port_no = 49152

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def random_string(length):
    # Source: https://stackoverflow.com/questions/2257441
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def send_packet(message, seq_no):
    iface = get_if()
    address = socket.gethostbyname(destination_ips[iface])
    print "Sending on interface %s to %s" % (iface, str(address))
    dport = random.randint(min_port_no, 65535)
    sport = random.randint(min_port_no, 65535)
    packet = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
    packet = packet / IP(dst = address) / TCP(dport = dport, sport = sport, seq = seq_no) / message
    packet.show2()
    hexdump(packet)
    sendp(packet, iface = iface, verbose = False)

def handle_packet(packet, max_seq_no):
    iface = get_if()
    if (TCP in packet and packet[TCP].dport >= min_port_no
        and packet[IP].dst == this_ip[iface] and packet[TCP].flags & 0x10): # ACK
        print "Got an response"
        packet.show2()
        hexdump(packet)
        sys.stdout.flush()
        # Send next packet
        next_seq = packet[TCP].ack
        if next_seq <= max_seq_no:
            send_packet(random_string(num_chars_per_packet), next_seq)

def main():

    if len(sys.argv) < 2:
        print 'Pass 1 argument: <max_seq_no>'
        exit(1)

    send_packet(random_string(num_chars_per_packet), 0)

    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    sniff(iface = ifaces[0], prn = lambda x: handle_packet(x, int(sys.argv[1])))

if __name__ == '__main__':
    main()

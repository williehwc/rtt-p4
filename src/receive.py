#!/usr/bin/env python2
import sys
import struct
import os
import time
import colored

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP

this_ip = {"h1-eth0": "10.0.1.1", "h2-eth0": "10.0.1.2"}
min_port_no = 49152

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def handle_packet(packet):
    iface = get_if()
    if (TCP in packet and packet[TCP].dport >= min_port_no
        and packet[IP].dst == this_ip[iface] and not packet[TCP].flags & 0x04): # RST
        print colored.fg("cyan")
        print "Got a packet"
        packet.show2()
        hexdump(packet)
        print colored.attr("reset")
        sys.stdout.flush()
        # Send ACK
        time.sleep(.5)
        print colored.fg("yellow")
        print "Sending ACK"
        ack_packet = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
        ack_packet = ack_packet / IP(src = packet[IP].dst, dst = packet[IP].src)
        ack_packet = ack_packet / TCP(sport = packet[TCP].dport, dport = packet[TCP].sport,
            flags = 'A', seq = packet[TCP].seq, ack = packet[TCP].seq + len(packet[TCP].load))
        ack_packet.show2()
        sendp(ack_packet, iface = iface, verbose = False)
        print colored.attr("reset")
        sys.stdout.flush()

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "Sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: handle_packet(x))

if __name__ == '__main__':
    main()

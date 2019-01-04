#!/usr/bin/env python2

import argparse, os, colored, time, socket, threading, random, signal, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, get_if_hwaddr, sniff, hexdump
from scapy.all import Ether, IP, TCP, Raw

THIS_IP = {"h1-eth0": "10.0.1.1", "h2-eth0": "10.0.1.2"}
DEST_IP = {"h1-eth0": "10.0.1.2", "h2-eth0": "10.0.1.1"}

MAX_SEQ_NO  = 2**32 # Exclusive

sent_pkt_timestamp = dict()
received_pkt_infos = []
mss = dict()
non_delayed_latencies = []

def print_pkt(args, pkt, inbound, latency, delayed, num_pkt_acked):
    color = "cyan"
    if inbound:
        color = "yellow"
    if args.print_pkt:
        print colored.fg(color)
        pkt.show2()
        hexdump(pkt)
        print colored.attr("reset")
    else:
        if inbound:
            print "IN  " + str(pkt[TCP].dport) + "<-" + str(pkt[TCP].sport),
        else:
            print "OUT " + str(pkt[TCP].sport) + "->" + str(pkt[TCP].dport),
        pkt_len = 0
        print " Seq: " + ("%10s" % pkt[TCP].seq),
        try:
            pkt_len = len(pkt[Raw].load)
        except:
            pass
        print " Len: " + ("%4s" % pkt_len),
        print " Lat: " + ("%4s" % latency),
        print " For: " + ("%4s" % num_pkt_acked),
        if pkt[TCP].flags & 0x02:
            print "SYN ",
        if pkt[TCP].flags & 0x10:
            print "ACK ",
        if delayed:
            print "delayed",
        print ""

def send_pkt(args, ack_no, message, flags, src_port, dest_port, latency, delayed, num_pkt_acked):
    seq_no = 0
    # If there was handshake, all packets excpet the SYN ACK packet should have seq no. of 1
    if (dest_port, src_port) in mss and "S" not in flags:
        seq_no = 1
    iface = args.iface
    address = socket.gethostbyname(DEST_IP[iface])
    options = []
    if "S" in flags:
        options = [('MSS', 0)]
    pkt = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst = address) / TCP(dport = dest_port, sport = src_port,
        seq = seq_no, ack = ack_no, flags = flags, options = options) / message
    print_pkt(args, pkt, False, latency, delayed, num_pkt_acked)
    sendp(pkt, iface = iface, verbose = False)
    sent_pkt_timestamp[(src_port, dest_port)] = time.time()

def handle_pkt(args, pkt):
    if TCP in pkt and pkt[IP].dst == THIS_IP[args.iface]:
        print_pkt(args, pkt, True, 0, False, 0)
        if not pkt[TCP].flags & 0x10: # not ACK
            if pkt[TCP].flags & 0x02: # SYN
                # Store the MSS
                mss[(pkt[TCP].sport, pkt[TCP].dport)] = dict(pkt[TCP].options)["MSS"]
            pkt_len = 0
            try:
                pkt_len = len(pkt[Raw].load)
            except:
                pass
            # Add to received_pkt_infos
            received_pkt_infos.append({
                "src_port"   : pkt[TCP].sport, # other port
                "dest_port"  : pkt[TCP].dport, # this port
                "timestamp"  : time.time(),
                "seq_no"     : pkt[TCP].seq,
                "payload_len": pkt_len,
                "syn"        : pkt[TCP].flags & 0x02
            })

def check_received_pkt_info(args):
    latest_received_pkt_infos = []
    while True:
        # Get latest received pkt for each tuple
        for received_pkt_info in received_pkt_infos:
            found_latest_received_pkt_info = False
            for i in range(len(latest_received_pkt_infos)):
                if (latest_received_pkt_infos[i]["src_port"] == received_pkt_info["src_port"] and
                    latest_received_pkt_infos[i]["dest_port"] == received_pkt_info["dest_port"]):
                        found_latest_received_pkt_info = True
                        if latest_received_pkt_infos[i]["timestamp"] < received_pkt_info["timestamp"]:
                            latest_received_pkt_infos[i] = received_pkt_info
            if not found_latest_received_pkt_info:
                latest_received_pkt_infos.append(received_pkt_info)
        # Send ACK if the received pkt's timestamp is after the last sent
        for latest_received_pkt_info in latest_received_pkt_infos:
            l = latest_received_pkt_info
            # Calculate latency
            latest_sent_pkt_timestamp = 0
            if (l["dest_port"], l["src_port"]) in sent_pkt_timestamp:
                latest_sent_pkt_timestamp = sent_pkt_timestamp[(l["dest_port"], l["src_port"])]
            delayed = l["payload_len"] < args.expected_payload_len
            if args.disable_delay:
                delayed = False
            elif (l["src_port"], l["dest_port"]) in mss:
                delayed = l["payload_len"] < mss[(l["src_port"], l["dest_port"])] and not l["syn"]
            latency = random.uniform(args.min_latency, args.max_latency)
            if delayed:
                latency += args.ack_delay
            # Send pkt if enough time has elapsed
            if (l["timestamp"] > latest_sent_pkt_timestamp and time.time() >= l["timestamp"] + latency):
                # How many packets are we ACKing?
                num_pkt_acked = 0
                for received_pkt_info in received_pkt_infos:
                    if (l["src_port"] == received_pkt_info["src_port"] and
                        l["dest_port"] == received_pkt_info["dest_port"] and
                        received_pkt_info["timestamp"] >= latest_sent_pkt_timestamp):
                            num_pkt_acked += 1
                # Flags
                flags = "A"
                if l["syn"]:
                    flags = "SA"
                # seq_no
                ack_no = (l["seq_no"] + l["payload_len"]) % MAX_SEQ_NO
                if l["syn"]:
                    ack_no = (l["seq_no"] + 1) % MAX_SEQ_NO
                # Send
                send_pkt(args, ack_no, "", flags, l["dest_port"], l["src_port"],
                    latency, delayed, num_pkt_acked)
                # Add latency to stats
                if not delayed:
                    non_delayed_latencies.append(latency)

def main(args):
    t = threading.Thread(target = check_received_pkt_info, args = (args,))
    t.daemon = True
    t.start()
    sniff(iface = args.iface, prn = lambda x: handle_pkt(args, x))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Unidirectional TCP/IP packet receiver')
    parser.add_argument('-a', dest='min_latency', help='Minimum latency in seconds',
                        type=float, action="store", required=False,
                        default=.5)
    parser.add_argument('-b', dest='max_latency', help='Maximum latency in seconds',
                        type=float, action="store", required=False,
                        default=.5)
    parser.add_argument('-x', dest='expected_payload_len', help='Expected payload length if no MSS',
                        type=int, action="store", required=False,
                        default=10)
    parser.add_argument('-i', dest='disable_delay', help='Disable delay',
                        action="store_true", required=False)
    parser.add_argument('-r', dest='ack_delay', help='ACK delay for small packets',
                        type=float, action="store", required=False,
                        default=.5)
    #parser.add_argument('-c', dest='combined_ack', help='Disable combined ACK',
    #                    action="store_false", required=False)
    parser.add_argument('-p', dest='print_pkt', help='Print entire packets',
                        action="store_true", required=False)
    #parser.add_argument('-v', dest='threshold', help='SLA latency in seconds (for statistics)',
    #                    type=float, action="store", required=False,
    #                    default=.5)
    args = parser.parse_args()
    args.iface = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))[0] # "h1-eth0" or "h2-eth0"
    main(args)
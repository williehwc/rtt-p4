#!/usr/bin/env python2
import argparse, random, math, os, socket, colored, string, time, logging, sys, signal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, get_if_hwaddr, sniff, hexdump
from scapy.all import Ether, IP, TCP, Raw

THIS_IP = {"h1-eth0": "10.0.1.1", "h2-eth0": "10.0.1.2"}
DEST_IP = {"h1-eth0": "10.0.1.2", "h2-eth0": "10.0.1.1"}

MIN_PORT_NO = 49152
MAX_PORT_NO = 2**16 # Exclusive
MAX_SEQ_NO  = 2**32 # Exclusive

latest_expected_ack_no = 0
sent_pkt_infos = []
non_delayed_latencies = []

def random_string(length):
    # Source: https://stackoverflow.com/questions/2257441
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def print_pkt(args, pkt, inbound, latency, delay_possible):
    return
    if not inbound:
        return
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
        print "Seq: " + ("%10s" % pkt[TCP].seq),
        print "Ack: " + ("%10s" % pkt[TCP].ack),
        pkt_len = 0
        try:
            pkt_len = len(pkt[Raw].load)
        except:
            pass
        print "Len: " + ("%4s" % pkt_len),
        print "Lat: " + ("%-15s" % latency),
        if pkt[TCP].flags & 0x02:
            print "SYN",
        if pkt[TCP].flags & 0x10:
            print "ACK",
        if delay_possible:
            print "dp",
        print ""

def send_pkt(args, seq_no, message, flags):
    global latest_expected_ack_no
    ack_no = 0
    # If handshake is enabled, all packets excpet the first SYN packet should have ACK no. of 1
    if args.handshake and "S" not in flags:
        ack_no = 1
    time.sleep(args.wait_time)
    iface = args.iface
    address = socket.gethostbyname(DEST_IP[iface])
    options = []
    expected_ack_no = seq_no + len(message)
    if "S" in flags:
        options = [('MSS', args.payload_len)]
        expected_ack_no = seq_no + 1
    pkt = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst = address) / TCP(dport = args.dest_port, sport = args.src_port,
        seq = seq_no, ack = ack_no, flags = flags, options = options) / message
    print_pkt(args, pkt, False, 0, False)
    latest_expected_ack_no = max(expected_ack_no, latest_expected_ack_no)
    sent_pkt_infos.append({
        "expected_ack_no": expected_ack_no,
        "timestamp"      : time.time(),
        "payload_len"    : len(message)
    })
    sendp(pkt, iface = iface, verbose = False)

def send_series(args, seq_no, final_seq_no):
    num_pkt = random.randint(args.min_num_pkt_per_series, args.max_num_pkt_per_series)
    for i in range(num_pkt):
        current_seq_no = seq_no + i * args.payload_len
        if current_seq_no <= final_seq_no:
            payload_len = args.payload_len
            if i == num_pkt - 1 and random.random() < args.probability_half_pkt_end:
                payload_len = int(math.floor(args.payload_len / 2))
            send_pkt(args, current_seq_no, random_string(payload_len), "")
        else:
            if args.log_file is not None and len(non_delayed_latencies) > 0:
                f = open(args.log_file, "w")
                f.write(str(sum(non_delayed_latencies) / len(non_delayed_latencies)))
                f.close()

def handle_pkt(args, pkt, final_seq_no):
    if (TCP in pkt and
        pkt[TCP].dport == args.src_port and
        pkt[TCP].sport == args.dest_port and
        pkt[IP].dst == THIS_IP[args.iface] and
        pkt[TCP].flags & 0x10): # ACK
            latency = 0
            for sent_pkt_info in sent_pkt_infos:
                if pkt[TCP].ack == sent_pkt_info["expected_ack_no"]:
                    latency = time.time() - sent_pkt_info["timestamp"]
                    if sent_pkt_info["payload_len"] == args.payload_len:
                        non_delayed_latencies.append(latency)
                    break
            delay_possible = sent_pkt_info["payload_len"] < args.payload_len and not pkt[TCP].flags & 0x02 # SYN
            print_pkt(args, pkt, True, latency, delay_possible)
            if pkt[TCP].ack == latest_expected_ack_no:
                # Send next pkt
                next_seq_no = pkt[TCP].ack
                if pkt[TCP].flags & 0x02: # SYN
                    send_pkt(args, next_seq_no, "", "A")
                send_series(args, next_seq_no, final_seq_no)

def main(args):
    # Calculate initial sequence number
    initial_seq_no = random.randint(0, MAX_SEQ_NO - 1)
    if args.seq_from_zero:
        initial_seq_no = 0
    # Calculate final sequence number based on args.num_pkt
    final_seq_no = (initial_seq_no + args.payload_len * (args.num_pkt - 1)) % MAX_SEQ_NO
    # If handshake is enabled, add 1 byte to final_seq_no for SYN packet, and send SYN packet
    if args.handshake:
        final_seq_no += 1
        send_pkt(args, initial_seq_no, "", "S")
    else:
        send_series(args, initial_seq_no, final_seq_no)
    # Start sniffing
    sniff(iface = args.iface, prn = lambda x: handle_pkt(args, x, final_seq_no))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Unidirectional TCP/IP packet sender')
    parser.add_argument('-t', dest='num_pkt', help='Total number of full packets to send (2 halves = 1 full)',
                        type=int, action="store", required=False,
                        default=1)
    parser.add_argument('-l', dest='payload_len', help='Payload length (number of bytes/characters)',
                        type=int, action="store", required=False,
                        default=10)
    parser.add_argument('-n', dest='min_num_pkt_per_series', help='Minimum number of packets per series',
                        type=int, action="store", required=False,
                        default=1)
    parser.add_argument('-m', dest='max_num_pkt_per_series', help='Maximum number of packets per series',
                        type=int, action="store", required=False,
                        default=1)
    parser.add_argument('-e', dest='probability_half_pkt_end', help='Prob. of ending a series with a half packet',
                        type=float, action="store", required=False,
                        default=0)
    parser.add_argument('-w', dest='wait_time', help='Wait time before sending packet',
                        type=float, action="store", required=False,
                        default=0)
    parser.add_argument('-d', dest='dest_port', help='Destination port number',
                        type=int, action="store", required=False,
                        default=random.randint(MIN_PORT_NO, MAX_PORT_NO - 1))
    parser.add_argument('-s', dest='src_port', help='Source port number',
                        type=int, action="store", required=False,
                        default=random.randint(MIN_PORT_NO, MAX_PORT_NO - 1))
    parser.add_argument('-p', dest='print_pkt', help='Print entire packets',
                        action="store_true", required=False)
    parser.add_argument('-k', dest='handshake', help='Turn on SYN handshake',
                        action="store_true", required=False)
    parser.add_argument('-z', dest='seq_from_zero', help='Sequence number starts at zero',
                        action="store_true", required=False)
    parser.add_argument('-f', dest='log_file', help='Log file path',
                        type=str, action="store", required=False,
                        default=None)
    args = parser.parse_args()
    args.iface = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))[0] # "h1-eth0" or "h2-eth0"
    main(args)
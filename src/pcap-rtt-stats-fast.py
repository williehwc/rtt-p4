# Update: This script has reduced RAM usage. It's slightly slower than the original
# "fast" script (also called pcap-rtt-stats-fast.py) but isn't very noticeable.
# Read a PCAP file and list all the flows and their RTT statistics
# This "fast" version assumes tshark RTTs are correct and does not consider MSS.
# Usage: python3 pcap-rtt-stats-fast.py path/to/file.pcap 0.1
# Output file with flows and RTT statistics is "path/to/file.pcap.fast.csv"
# Note: Replace 0.1 with the replay speed. Assume 1 if omitted.
# Also outputs an actual RTTs CSV ("path/to/file.pcap.fast.rtts.csv") file with columns:
# RTT (microsec), frame no., sip (of ACK packet), dip, spt, dpt, seq, ack, stream no.

import sys, subprocess, statistics, os
import ijson.backends.yajl2_c as ijson

TSHARK_COMMAND = [
    "tshark",
    "-r", sys.argv[1],
    "-j", "tcp",
    "-T", "json",
    "-e", "frame.number",
    "-e", "tcp.stream",
    "-e", "ip.src",
    "-e", "tcp.srcport",
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "tcp.seq",
    # "-e", "tcp.len",
    "-e", "tcp.ack",
    # "-e", "tcp.flags.syn",
    # "-e", "tcp.flags.ack",
    # "-e", "tcp.options.mss_val",
    "-e", "tcp.analysis.ack_rtt",
    "-e", "tcp.analysis.initial_rtt",
    # "-e", "frame.time_epoch",
    "-o", "tcp.relative_sequence_numbers:FALSE"
]

class Flows:
    def __init__(self):
        self.flows = dict()
    def update(self, packet):
        key = "%d,%s,%s,%d,%d" % (packet["tcp.stream"], packet["ip.dst"],
            packet["ip.src"], packet["tcp.dstport"], packet["tcp.srcport"])
        if key not in self.flows:
            irtt = -1
            if "tcp.analysis.initial_rtt" in packet:
                irtt = packet["tcp.analysis.initial_rtt"]
            self.flows[key] = {
                "tcp.stream": packet["tcp.stream"],
                "ip.src": packet["ip.dst"],
                "ip.dst": packet["ip.src"],
                "tcp.srcport": packet["tcp.dstport"],
                "tcp.dstport": packet["tcp.srcport"],
                "tcp.analysis.initial_rtt": irtt,
                "ack_indices_and_rtts": [] # list of tuples
            }
        # assert(self.flows[key]["tcp.analysis.initial_rtt"] < 0 or
        #     packet["tcp.analysis.initial_rtt"] == self.flows[key]["tcp.analysis.initial_rtt"])
        self.flows[key]["ack_indices_and_rtts"].append((packet["frame.number"], packet["tcp.analysis.ack_rtt"]))
    def to_csv(self, csv_file):
        csv_file.write("str,sip,spt,dip,dpt,num,avg,std,ini,idx\n")
        for _, flow in self.flows.items():
            stdev = 0
            if len(flow["ack_indices_and_rtts"]) > 1:
                stdev = statistics.stdev([x[1] for x in flow["ack_indices_and_rtts"]])
            csv_file.write("%d,%s,%d,%s,%d,%d,%f,%f,%f,%s\n" %
                (
                    flow["tcp.stream"],
                    flow["ip.src"],
                    flow["tcp.srcport"],
                    flow["ip.dst"],
                    flow["tcp.dstport"],
                    len(flow["ack_indices_and_rtts"]),
                    statistics.mean([x[1] for x in flow["ack_indices_and_rtts"]]),
                    stdev,
                    flow["tcp.analysis.initial_rtt"],
                    " ".join([str(x[0]) for x in flow["ack_indices_and_rtts"]])
                )
            )

def preprocess_packet(pc):
    packet = pc["_source"]["layers"]
    for key in packet:
        try:
            packet[key] = int(packet[key][0])
        except:
            try:
                packet[key] = float(packet[key][0])
            except:
                packet[key] = packet[key][0]
    return packet

def main():
    # Check if sys.argv[3] (output path) is specified
    out_filename = sys.argv[1]
    if len(sys.argv) > 3:
        if (sys.argv[3]).endswith("/") or (sys.argv[3]).endswith("\\"):
            print("Remove final slash from output path")
            sys.exit(1)
        out_filename = sys.argv[3] + "/" + os.path.basename(sys.argv[1])

    # Run tshark to generate the JSON
    tshark_result = subprocess.run(TSHARK_COMMAND, stdout=subprocess.PIPE)
    with open(out_filename + '.fast.json', 'wb') as json_file:
        json_file.write(tshark_result.stdout)
    del tshark_result

    # Read the JSON
    json_file = open(out_filename + '.fast.json', 'rb')
    packet_capture = ijson.items(json_file, "item")

    # Initialize object instances
    flows = Flows()

    # Open RTTs file for writing
    rtts_file = open(out_filename + '.fast.rtts.csv', "w")
    replay_speed = 1
    if len(sys.argv) > 2:
        replay_speed = float((sys.argv[2]).replace('!', ''))

    # Iterate over packet_capture
    for pc in packet_capture:
        this_packet = preprocess_packet(pc)
        if "tcp.stream" in this_packet and "tcp.analysis.ack_rtt" in this_packet:
            flows.update(this_packet)
            rtts_file.write("%f,%d,%s,%s,%d,%d,%d,%d,%d\n" % (
                this_packet["tcp.analysis.ack_rtt"] * 1000000 / replay_speed,
                this_packet["frame.number"],
                this_packet["ip.src"],
                this_packet["ip.dst"],
                this_packet["tcp.srcport"],
                this_packet["tcp.dstport"],
                this_packet["tcp.seq"],
                this_packet["tcp.ack"],
                this_packet["tcp.stream"]
            ))

    # Write results to CSV
    with open(out_filename + '.fast.csv', "w") as csv_file:
        flows.to_csv(csv_file)

main()
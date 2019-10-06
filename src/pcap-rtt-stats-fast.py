# Update: This script has reduced RAM usage. It's slightly slower than the original
# "fast" script (also called pcap-rtt-stats-fast.py) but isn't very noticeable.
# Read a PCAP file and list all the flows and their RTT statistics
# This "fast" version assumes tshark RTTs are correct and does not consider MSS.
# Usage: python3 pcap-rtt-stats-fast.py path/to/file.pcap 0.1
# Output file with flows and RTT statistics is "path/to/file.pcap.fast.csv"
# Note: Replace 0.1 with the replay speed. Assume 1 if omitted.
# Also outputs an actual RTTs CSV ("path/to/file.pcap.fast.rtts.csv") file with columns:
# RTT (microsec), frame no., sip (of ACK packet), dip, spt, dpt, seq, ack, stream no.

import sys, subprocess, statistics, os, csv

TSHARK_COMMAND_WITHOUT_FIELDS = [
    "tshark",
    "-r", sys.argv[1],
    "-j", "tcp",
    "-T", "fields",
    "-o", "tcp.relative_sequence_numbers:FALSE"
]

FIELDS = [
    "frame.number",
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.initial_rtt"
]

# Complete the tshark command
tshark_command = TSHARK_COMMAND_WITHOUT_FIELDS
for field in FIELDS:
    tshark_command.extend(["-e", field])

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
    packet = dict()
    for i, field in enumerate(FIELDS):
        if pc[i] != "":
            try:
                packet[field] = int(pc[i])
            except:
                try:
                    packet[field] = float(pc[i])
                except:
                    packet[field] = pc[i]
    return packet

def main():
    # Check if sys.argv[3] (output path) is specified
    out_filename = sys.argv[1]
    if len(sys.argv) > 3:
        if (sys.argv[3]).endswith("/") or (sys.argv[3]).endswith("\\"):
            print("Remove final slash from output path")
            sys.exit(1)
        out_filename = sys.argv[3] + "/" + os.path.basename(sys.argv[1])

    # Run tshark to generate the tsv
    tshark_result = subprocess.run(tshark_command, stdout=subprocess.PIPE)
    with open(out_filename + '.fast.tsv', 'wb') as tsv_file:
        tsv_file.write(tshark_result.stdout)
    del tshark_result

    # Read the TSV
    tsv_file = open(out_filename + '.fast.tsv')
    packet_capture = csv.reader(tsv_file, delimiter='\t')

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
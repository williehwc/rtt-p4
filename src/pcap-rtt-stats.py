# Read a PCAP file and list all the flows and their RTT statistics
# Usage: python3 pcap-rtt-stats.py path/to/file.pcap

import sys, subprocess, json, statistics

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
    "-e", "tcp.len",
    "-e", "tcp.ack",
    "-e", "tcp.flags.syn",
    "-e", "tcp.flags.ack",
    "-e", "tcp.options.mss_val",
    "-e", "tcp.analysis.ack_rtt",
    "-e", "tcp.analysis.initial_rtt",
    "-e", "frame.time_epoch"
]

DEFAULT_MSS = 1460

def lookup_mss(packet, packets_with_mss):
    for p in packets_with_mss:
        if  packet["tcp.stream"] == p["tcp.stream"] \
        and packet["ip.src"] == p["ip.src"] \
        and packet["ip.dst"] == p["ip.dst"] \
        and packet["tcp.srcport"] == p["tcp.srcport"] \
        and packet["tcp.dstport"] == p["tcp.dstport"]:
            # print("Found MSS of", p["tcp.options.mss_val"], "for packet",
            #     packet["frame.number"], "in packet", p["frame.number"])
            return p["tcp.options.mss_val"]
    # print("Couldn't find MSS for packet", packet["frame.number"], "– assuming default of", DEFAULT_MSS)
    return DEFAULT_MSS

class Packets:
    def __init__(self):
        self.packets = dict()
    def try_append(self, packet, packets_with_mss):
        try:
            if int(packet["tcp.len"]) >= lookup_mss(packet, packets_with_mss):
                expected_ack = packet["tcp.seq"] + packet["tcp.len"]
                if packet["tcp.flags.syn"] == 1:
                    expected_ack += 1
                self.packets["%d,%s,%s,%d,%d,%d" % (
                    packet["tcp.stream"],
                    packet["ip.src"],
                    packet["ip.dst"],
                    packet["tcp.srcport"],
                    packet["tcp.dstport"],
                    expected_ack
                )] = {
                    "frame.time_epoch": packet["frame.time_epoch"],
                    "frame.number": packet["frame.number"]
                }
        except:
            pass
    def try_ack(self, new_packet):
        # Criteria: IP address, ports, and stream number match. Also, ACK = SEQ + LEN
        if new_packet["tcp.flags.ack"] == 1:
            key = "%d,%s,%s,%d,%d,%d" % (
                new_packet["tcp.stream"],
                new_packet["ip.dst"],
                new_packet["ip.src"],
                new_packet["tcp.dstport"],
                new_packet["tcp.srcport"],
                new_packet["tcp.ack"]
            )
            packet = self.packets.pop(key, None)
            if packet is not None:
                rtt = new_packet["frame.time_epoch"] - packet["frame.time_epoch"]
                expected_rtt = -1
                if "tcp.analysis.ack_rtt" in new_packet:
                    expected_rtt = new_packet["tcp.analysis.ack_rtt"]
                print(new_packet["frame.number"], "acks", packet["frame.number"], "with actual RTT",
                    rtt, "–", expected_rtt, "sec expected")
                return rtt
        return None

class Flows:
    def __init__(self):
        self.flows = dict()
    def update(self, packet, rtt):
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
        self.flows[key]["ack_indices_and_rtts"].append((packet["frame.number"], rtt))
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
    # Run tshark to generate the JSON
    tshark_result = subprocess.run(TSHARK_COMMAND, stdout=subprocess.PIPE)
    with open(sys.argv[1] + '.json', 'wb') as json_file:
        json_file.write(tshark_result.stdout)

    # Read the JSON
    packet_capture = json.loads(tshark_result.stdout.decode("utf-8"))

    # Initialize object instances
    packets_awaiting_ack = Packets()
    flows = Flows()

    # Iterate over packet_capture
    all_packets = [preprocess_packet(pc) for pc in packet_capture]
    packets_with_mss = [p for p in all_packets if "tcp.options.mss_val" in p and "tcp.stream" in p]
    for this_packet in all_packets:
        if "tcp.stream" not in this_packet:
            continue
        packets_awaiting_ack.try_append(this_packet, packets_with_mss)
        this_rtt = packets_awaiting_ack.try_ack(this_packet)
        if this_rtt is not None:
            flows.update(this_packet, this_rtt)

    # Write results to CSV
    with open(sys.argv[1] + '.csv', "w") as csv_file:
        flows.to_csv(csv_file)

main()
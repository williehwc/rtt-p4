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

def lookup_mss(packet, all_packets):
    for p in all_packets:
        if  "tcp.stream" in p \
        and packet["tcp.stream"] == p["tcp.stream"] \
        and packet["ip.src"] == p["ip.src"] \
        and packet["ip.dst"] == p["ip.dst"] \
        and packet["tcp.srcport"] == p["tcp.srcport"] \
        and packet["tcp.dstport"] == p["tcp.dstport"] \
        and "tcp.options.mss_val" in p:
            # print("Found MSS of", p["tcp.options.mss_val"], "for packet",
            #     packet["frame.number"], "in packet", p["frame.number"])
            return p["tcp.options.mss_val"]
    print("Couldn't find MSS for packet", packet["frame.number"], "– assuming default of", DEFAULT_MSS)
    return DEFAULT_MSS

class Packets:
    def __init__(self):
        self.packets = []
    def try_append(self, packet, all_packets):
        mss = lookup_mss(packet, all_packets)
        if int(packet["tcp.len"]) >= mss:
            self.packets.append(packet)
    def try_ack(self, new_packet):
        for i, packet in enumerate(self.packets):
            # Criteria: IP address, ports, and stream number match. Also, ACK = SEQ + LEN
            if  new_packet["tcp.flags.ack"] == 1 \
            and packet["tcp.stream"] == new_packet["tcp.stream"] \
            and packet["ip.src"] == new_packet["ip.dst"] \
            and packet["ip.dst"] == new_packet["ip.src"] \
            and packet["tcp.srcport"] == new_packet["tcp.dstport"] \
            and packet["tcp.dstport"] == new_packet["tcp.srcport"]:
                expected_ack = packet["tcp.seq"] + packet["tcp.len"]
                if packet["tcp.flags.syn"] == 1:
                    expected_ack += 1
                if new_packet["tcp.ack"] == expected_ack:
                    self.packets.pop(i)
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
        self.flows = []
    def find(self, tcp_stream, ip_src, ip_dst, tcp_srcport, tcp_dstport):
        for i, flow in enumerate(self.flows):
            if  flow["tcp.stream"] == tcp_stream \
            and flow["ip.src"] == ip_src \
            and flow["ip.dst"] == ip_dst \
            and flow["tcp.srcport"] == tcp_srcport \
            and flow["tcp.dstport"] == tcp_dstport:
                return i
        return None
    def append(self, tcp_stream, ip_src, ip_dst, tcp_srcport, tcp_dstport, irtt):
        new_flow = {
            "tcp.stream": tcp_stream,
            "ip.src": ip_src,
            "ip.dst": ip_dst,
            "tcp.srcport": tcp_srcport,
            "tcp.dstport": tcp_dstport,
            "tcp.analysis.initial_rtt": irtt,
            "ack_indices_and_rtts": [] # list of tuples
        }
        self.flows.append(new_flow)
    def update(self, packet, rtt):
        flow_index = self.find(packet["tcp.stream"], packet["ip.dst"],
            packet["ip.src"], packet["tcp.dstport"], packet["tcp.srcport"])
        if flow_index is None:
            flow_index = len(self.flows)
            irtt = -1
            if "tcp.analysis.initial_rtt" in packet:
                irtt = packet["tcp.analysis.initial_rtt"]
            self.append(packet["tcp.stream"], packet["ip.dst"], packet["ip.src"],
                packet["tcp.dstport"], packet["tcp.srcport"], irtt)
        assert(self.flows[flow_index]["tcp.analysis.initial_rtt"] < 0 or
            packet["tcp.analysis.initial_rtt"] == self.flows[flow_index]["tcp.analysis.initial_rtt"])
        self.flows[flow_index]["ack_indices_and_rtts"].append((packet["frame.number"], rtt))
    def to_csv(self, csv_file):
        csv_file.write("str,sip,spt,dip,dpt,num,avg,std,ini,idx\n")
        for flow in self.flows:
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
    for this_packet in all_packets:
        if "tcp.stream" not in this_packet:
            continue
        packets_awaiting_ack.try_append(this_packet, all_packets)
        this_rtt = packets_awaiting_ack.try_ack(this_packet)
        if this_rtt is not None:
            flows.update(this_packet, this_rtt)

    # Write results to CSV
    with open(sys.argv[1] + '.csv', "w") as csv_file:
        flows.to_csv(csv_file)

main()
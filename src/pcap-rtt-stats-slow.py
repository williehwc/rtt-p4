# Update: This is the reduced RAM usage version of pcap-rtt-stats.py. It is noticeably
# slower, which necessitates making this a separate "slow" version of the original script.
# Read a PCAP file and list all the flows and their RTT statistics
# Usage: python3 pcap-rtt-stats.py path/to/file.pcap 0.1
# Output file with flows and RTT statistics is "path/to/file.pcap.csv"
# Note: Replace 0.1 with the replay speed. Assume 1 if omitted.
# Also outputs an actual RTTs CSV ("path/to/file.pcap.rtts.csv") file with columns:
# RTT (microsec), frame no., sip (of ACK packet), dip, spt, dpt, seq, ack, stream no.

import sys, subprocess, statistics
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
    del tshark_result

    # Read the JSON and get MSS's
    json_file = open(sys.argv[1] + '.json', 'rb')
    packet_capture = ijson.items(json_file, "item")
    packets_with_mss = [preprocess_packet(pc) for pc in packet_capture if
                        "tcp.options.mss_val" in pc["_source"]["layers"] and
                        "tcp.stream" in pc["_source"]["layers"]]
    json_file.close()

    # Read the JSON again
    json_file = open(sys.argv[1] + '.json', 'rb')
    packet_capture = ijson.items(json_file, "item")

    # Initialize object instances
    packets_awaiting_ack = Packets()
    flows = Flows()

    # Open RTTs file for writing
    rtts_file = open(sys.argv[1] + '.rtts.csv', "w")
    replay_speed = 1
    if len(sys.argv) > 2:
        replay_speed = float(sys.argv[2])

    # Iterate over packet_capture
    for pc in packet_capture:
        this_packet = preprocess_packet(pc)
        if "tcp.stream" not in this_packet:
            continue
        packets_awaiting_ack.try_append(this_packet, packets_with_mss)
        this_rtt = packets_awaiting_ack.try_ack(this_packet)
        if this_rtt is not None:
            flows.update(this_packet, this_rtt)
            rtts_file.write("%f,%d,%s,%s,%d,%d,%d,%d,%d\n" % (
                this_rtt * 1000000 / replay_speed,
                this_packet["frame.number"],
                this_packet["ip.src"],
                this_packet["ip.dst"],
                this_packet["tcp.srcport"],
                this_packet["tcp.dstport"],
                this_packet["tcp.seq"],
                this_packet["tcp.ack"],
                this_packet["tcp.stream"]
            ))

    rtts_file.close()

    # Write results to CSV
    with open(sys.argv[1] + '.csv', "w") as csv_file:
        flows.to_csv(csv_file)

main()
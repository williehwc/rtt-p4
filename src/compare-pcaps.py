# WORK IN PROGRESS!!!
# Compared an observed PCAP against a standard PCAP w.r.t. TCP packets
# Only works for observed PCAP that corresponds one-to-one with the standard PCAP
# For example, if the standard PCAP was replayed twice, do not use this script
# All "tcp" and "ip" header fields as defined in TSHARK_COMMAND are compared
# Usage: python3 compare-pcaps.py standard.pcap observed.pcap

import sys, subprocess, json, pandas

def tshark_command(filename):
    return [
        "tshark",
        "-r", filename,
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
        "-e", "tcp.analysis.ack_rtt",
        "-e", "tcp.analysis.initial_rtt",
        "-e", "frame.time_epoch"
    ]

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
    tshark_result = subprocess.run(tshark_command(sys.argv[1]), stdout=subprocess.PIPE)
    standard_packet_capture = json.loads(tshark_result.stdout.decode("utf-8"))
    tshark_result = subprocess.run(tshark_command(sys.argv[2]), stdout=subprocess.PIPE)
    observed_packet_capture = json.loads(tshark_result.stdout.decode("utf-8"))
    del tshark_result

    matched_packets = []

    standard_packets = [preprocess_packet(pc) for pc in standard_packet_capture]
    observed_packets = [preprocess_packet(pc) for pc in observed_packet_capture]
    for o, observed_packet in enumerate(observed_packets):
        for s, standard_packet in enumerate(standard_packets):
            matched = True
            for tc in tshark_command(""):
                if tc.startswith("tcp.") or tc.startswith("ip."):
                    try:
                        if observed_packet[tc] != standard_packet[tc]:
                            matched = False
                    except:
                        matched = False
                        break
            if matched:
                standard_packet["TIMEDIFF"] = \
                    observed_packet["frame.time_epoch"] - standard_packet["frame.time_epoch"]
                matched_packets.append(standard_packet)
                del observed_packets[o]
                del standard_packets[s]
                break
    
    pandas.DataFrame(matched_packets).to_csv("matched_packets.csv")
    pandas.DataFrame(observed_packets).to_csv("observed_packets.csv")
    pandas.DataFrame(standard_packets).to_csv("standard_packets.csv")

main()
# Usage: python3 pcap-kde.py path/to/file.pcap
# Output: KDE plot of packets across time
#         scatterplot frame number vs time

import sys, subprocess, json, seaborn
from matplotlib import pyplot

TSHARK_COMMAND = [
    "tshark",
    "-r", sys.argv[1],
    "-T", "json",
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

    # Run tshark to generate the JSON, then read the JSON
    tshark_result = subprocess.run(TSHARK_COMMAND, stdout=subprocess.PIPE)
    packet_capture = json.loads(tshark_result.stdout.decode("utf-8"))

    frame_times = []

    # Iterate over packet_capture
    all_packets = [preprocess_packet(pc) for pc in packet_capture]
    for this_packet in all_packets:
        frame_times.append(this_packet["frame.time_epoch"])

    # KDE plot of packets across time
    kde_plot = seaborn.distplot(frame_times)
    kde_plot.set(xlabel="Timestamp")
    kde_plot.figure.savefig(sys.argv[1] + ".kde.png")

    # Scatterplot frame number vs time
    pyplot.scatter(range(len(frame_times)), frame_times, s=1)
    pyplot.xlim(0, len(frame_times))
    pyplot.ylim(min(frame_times), max(frame_times))
    pyplot.xlabel("Frame number")
    pyplot.ylabel("Timestamp")
    pyplot.savefig(sys.argv[1] + ".scatter.png")

main()
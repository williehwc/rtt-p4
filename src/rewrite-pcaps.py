# Rewrite destination MAC address with timestamp (in microsec)
# Change actual timestamp to (UNIX epoch + 0.001 * frame no.) sec
# Usage: python3 rewrite-pcaps.py smallFlows.pcap

import sys
from pypacker import ppcap
from pypacker.layer12 import ethernet

preader = ppcap.Reader(filename=sys.argv[1])
pwriter = ppcap.Writer(filename=sys.argv[1] + ".rewritten.pcap")

for ts_nano, buf in preader:
    eth = ethernet.Ethernet(buf)
    ts_micro = int(ts_nano / 1000) % 281474976710655
    ts_micro_hex = (ts_micro).to_bytes(6, "big").hex()
    eth.dst_s = ts_micro_hex
    pwriter.write(eth.bin())

pwriter.close()
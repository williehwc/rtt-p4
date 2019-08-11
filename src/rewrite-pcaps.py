# Rewrite destination MAC address with timestamp (in millisec)
# Change actual timestamp to (UNIX epoch + 0.001 * frame no.) sec
# Usage: python3 rewrite-pcaps.py smallFlows.pcap

import sys
from pypacker import ppcap
from pypacker.layer12 import ethernet

preader = ppcap.Reader(filename=sys.argv[1])
pwriter = ppcap.Writer(filename=sys.argv[1] + ".rewritten.pcap")

for ts_nano, buf in preader:
    eth = ethernet.Ethernet(buf)
    ts_milli = int(ts_nano / 1000000)
    ts_milli_hex = (ts_milli).to_bytes(6, "big").hex()
    eth.dst_s = ts_milli_hex
    pwriter.write(eth.bin())

pwriter.close()
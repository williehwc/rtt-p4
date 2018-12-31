#!/usr/bin/env python2
import sys, subprocess

def main(num_flows, other_args):
    procs = [subprocess.Popen(["./send.py"] + other_args) for i in range(num_flows)]
    raw_input('Press Enter to quit\n')
    for p in procs:
        p.kill()

if __name__ == '__main__':
    if len(sys.argv) < 2 or "-s" in sys.argv or "-d" in sys.argv or "-h" in sys.argv:
        print 'Arguments: <Number of flows> <Other arguments for send.py (optional)>'
        print 'Arguments may include neither -s (src port) nor -d (dest port)'
        exit(1)
    main(int(sys.argv[1]), sys.argv[2:len(sys.argv)])
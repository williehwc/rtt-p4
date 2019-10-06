#!/usr/bin/env python2
import sys, subprocess, signal

procs = []

def signal_handler(sig, frame):
    for p in procs:
        p.kill()

def main(num_flows, log_file_suffix, other_args):
    for i in range(num_flows):
        if log_file_suffix == "_":
            proc = subprocess.Popen(["./send.py"] + other_args)
            procs.append(proc)
        else:
            proc = subprocess.Popen(["./send.py", "-f", str(i) + "_" + log_file_suffix] + other_args)
            procs.append(proc)
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()    

if __name__ == '__main__':
    if len(sys.argv) < 2 or "-s" in sys.argv or "-d" in sys.argv \
    or "-h" in sys.argv or "--help" in sys.argv or "-f" in sys.argv:
        print 'Arguments: <Number of flows> <_ or log file suffix> <Other arguments for send.py (optional)>'
        print 'Arguments may not include -f (log file), -s (src port), or -d (dest port)'
        exit(1)
    main(int(sys.argv[1]), sys.argv[2], sys.argv[3:len(sys.argv)])
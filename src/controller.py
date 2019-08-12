#!/usr/bin/env python2

# Usage: ./legacy-controller.py -r > path/to/observed_rtts_filename.csv
# Output columns:
# RTT (microsec), register index of RTT, sip (of ACK packet), dip, spt, dpt, seq, ack

from __future__ import print_function
import sys, time, pexpect, re, socket, argparse

TABLE_SIZE = 120
NUM_TABLES = 2

INITIAL_FILTER_PERCENT = 0

def int_to_ip(ip):
    # Convert int to IP address: https://stackoverflow.com/questions/5619685/    
    return socket.inet_ntoa(hex(ip)[2:].zfill(8).decode('hex'))

def run_thrift_command(thrift, command):
    if command is not None:
        thrift.sendline(command)
    thrift.expect('RuntimeCmd: ')
    return thrift.before

def parse_thrift_register(thrift_output):
    return [int(rtt_string) for rtt_string in re.findall(r'\d+', thrift_output)]

def main(args):
    rtts = []
    thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
    run_thrift_command(thrift, None) # Cue up the command line interface
    # Initialize tuning parameters
    run_thrift_command(thrift, 'register_write latency_threshold 0 ' + str(args.initial_stale_threshold))
    run_thrift_command(thrift, 'register_write filter_percent 0 ' + str(INITIAL_FILTER_PERCENT))
    if args.reset:
        run_thrift_command(thrift, 'register_reset timestamps')
        run_thrift_command(thrift, 'register_reset keys')
    while True:
        time.sleep(args.sleep)
        # Issue read commands
        current_rtts_thrift_output = run_thrift_command(thrift, 'register_read rtts')
        current_register_indices_of_rtts_thrift_output = \
            run_thrift_command(thrift, 'register_read register_indices_of_rtts')
        current_src_ips_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read src_ips_of_rtts')
        current_dst_ips_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read dst_ips_of_rtts')
        current_src_ports_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read src_ports_of_rtts')
        current_dst_ports_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read dst_ports_of_rtts')
        current_seq_nos_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read seq_nos_of_rtts')
        current_ack_nos_of_rtts_thrift_output = run_thrift_command(thrift, 'register_read ack_nos_of_rtts')
        current_timestamps_thrift_output = run_thrift_command(thrift, 'register_read timestamps')
        current_latency_threshold_thrift_output = run_thrift_command(thrift, 'register_read latency_threshold')
        #current_filter_percent_thrift_output = run_thrift_command(thrift, 'register_read filter_percent')
        # Issue reset commands
        run_thrift_command(thrift, 'register_reset rtts')
        run_thrift_command(thrift, 'register_reset register_indices_of_rtts')
        run_thrift_command(thrift, 'register_reset src_ips_of_rtts')
        run_thrift_command(thrift, 'register_reset dst_ips_of_rtts')
        run_thrift_command(thrift, 'register_reset src_ports_of_rtts')
        run_thrift_command(thrift, 'register_reset dst_ports_of_rtts')
        run_thrift_command(thrift, 'register_reset seq_nos_of_rtts')
        run_thrift_command(thrift, 'register_reset ack_nos_of_rtts')
        run_thrift_command(thrift, 'register_reset current_rtt_index')
        # Process new RTTs
        new_rtts_etc = []
        current_rtts = parse_thrift_register(current_rtts_thrift_output)
        current_register_indices_of_rtts = \
            parse_thrift_register(current_register_indices_of_rtts_thrift_output)
        current_src_ips_of_rtts = parse_thrift_register(current_src_ips_of_rtts_thrift_output)
        current_dst_ips_of_rtts = parse_thrift_register(current_dst_ips_of_rtts_thrift_output)
        current_src_ports_of_rtts = parse_thrift_register(current_src_ports_of_rtts_thrift_output)
        current_dst_ports_of_rtts = parse_thrift_register(current_dst_ports_of_rtts_thrift_output)
        current_seq_nos_of_rtts = parse_thrift_register(current_seq_nos_of_rtts_thrift_output)
        current_ack_nos_of_rtts = parse_thrift_register(current_ack_nos_of_rtts_thrift_output)
        for i in range(len(current_rtts)):
            if current_rtts[i] > 0 and current_register_indices_of_rtts[i] < TABLE_SIZE * NUM_TABLES:
            # if current_rtts[i] > 0 and current_register_indices_of_rtts[i] < TABLE_SIZE * NUM_TABLES \
            #     and current_rtts[i] <= MAX_REPORTABLE_RTT:
                rtts.append(current_rtts[i])
                new_rtts_etc.append((
                    current_rtts[i],
                    current_register_indices_of_rtts[i],
                    int_to_ip(current_src_ips_of_rtts[i]),
                    int_to_ip(current_dst_ips_of_rtts[i]),
                    current_src_ports_of_rtts[i],
                    current_dst_ports_of_rtts[i],
                    current_seq_nos_of_rtts[i],
                    current_ack_nos_of_rtts[i]
                ))
        # Check the occupancies of timestamp register
        current_timestamps = parse_thrift_register(current_timestamps_thrift_output)
        occupancies = []
        for i in range(NUM_TABLES):
            occupancy = len([t for t in current_timestamps[(i*TABLE_SIZE):((i+1)*TABLE_SIZE)] if t != 0])
            occupancies.append(occupancy)
        # Chceck tuning parameters
        current_latency_threshold = parse_thrift_register(current_latency_threshold_thrift_output)[0]
        #current_filter_percent = parse_thrift_register(current_filter_percent_thrift_output)[0]
        # Print statistics
        if args.threshold > 0:
            print("--------------------------------------")
            print("# pkts processed:              " + str(len(rtts)))
            print("# pkts exceeding threshold:    " + str(len([rtt for rtt in rtts if rtt > args.threshold])))
            print("# pkts at or below threshold:  " + str(len([rtt for rtt in rtts if rtt <= args.threshold])))
            if len(rtts) > 0:
                print("Average RTT:                   " + str(sum(rtts) / len(rtts)))
            if len(new_rtts_etc) > 0:
                print("New RTTs and register indices:", new_rtts_etc)
            print("Occupancies of registers:      " + str(sum(occupancies)), occupancies)
            print("Stale RTT threshold:           " + str(current_latency_threshold))
            #print("Filter percent for sampling:   " + str(current_filter_percent))
        else:
            for new_rtt_etc in new_rtts_etc:
                print("%d,%d,%s,%s,%d,%d,%d,%d" % new_rtt_etc)
            if args.print_register_occupancy:
                print(occupancies, "(Recorded", len(rtts), "RTTs)", file=sys.stderr)

def premain():
    parser = argparse.ArgumentParser(description='Controller for RTT-P4')
    parser.add_argument('-t', '--threshold', dest='threshold', type=int,
        help='RTT SLA threshold in microseconds (default is 0, which means logging mode)',
        action="store", required=False, default=0)
    parser.add_argument('-r', '--reset', dest='reset',
        help='Reset timestamps and keys registers',
        action="store_true", required=False)
    parser.add_argument('-i', '--initial', dest='initial_stale_threshold', type=int,
        help='Initial stale threshold in microseconds (default 500000)',
        action="store", required=False, default=500000)
    # parser.add_argument('-a', '--auto', dest='auto_tune_stale_threshold_percentile', type=int,
    #     help='Autotune stale threshold percentile (0 to 100 inclusive)',
    #     action="store", required=False, default=None)
    # parser.add_argument('-l', '--last', dest='auto_tune_num_recent_rtts', type=int,
    #     help='Number of most recent RTTs to consider when autotuning stale threshold (0 means last batch)',
    #     action="store", required=False, default=None)
    # parser.add_argument('-m', '--max', dest='max_stale_rtt', type=int,
    #     help='Maximum stale RTT in microseconds',
    #     action="store", required=False, default=1000000)
    parser.add_argument('-p', '--print', dest='print_register_occupancy',
        help='Print occupancy of registers',
        action="store_true", required=False)
    parser.add_argument('-s', '--sleep', dest='sleep', type=int,
        help='Sleep duration (refresh rate) in seconds (default is 5)',
        action="store", required=False, default=5)
    args = parser.parse_args()
    main(args)

if __name__ == '__main__':
    premain()

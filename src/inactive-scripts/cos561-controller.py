#!/usr/bin/env python2
import sys, time, pexpect, re, argparse

def run_thrift_cmd(thrift, cmd):
    if cmd is not None:
        thrift.sendline(cmd)
    thrift.expect('RuntimeCmd: ')
    return thrift.before

def parse_thrift_register(thrift_output):
    thrift_output_lines = thrift_output.splitlines()
    return [int(rtt_string) for rtt_string in re.findall(r'\d+', thrift_output)]

def get_new_rtts_and_register_indices(thrift, args):
    # Issue read cmds
    current_rtts_thrift_output = run_thrift_cmd(thrift, 'register_read rtts')
    current_register_indices_of_rtts_thrift_output = \
        run_thrift_cmd(thrift, 'register_read register_indices_of_rtts')
    # Issue reset cmds
    run_thrift_cmd(thrift, 'register_reset rtts')
    run_thrift_cmd(thrift, 'register_reset register_indices_of_rtts')
    run_thrift_cmd(thrift, 'register_reset current_rtt_index')
    # Process new RTTs
    new_rtts_and_register_indices = []
    current_rtts = parse_thrift_register(current_rtts_thrift_output)
    current_register_indices_of_rtts = \
        parse_thrift_register(current_register_indices_of_rtts_thrift_output)
    for i in range(len(current_rtts)):
        if current_rtts[i] > 0 and current_register_indices_of_rtts[i] < args.table_size * args.num_tables \
            and current_rtts[i] <= args.max_reportable_rtt:
            new_rtts_and_register_indices.append((current_rtts[i], current_register_indices_of_rtts[i]))
    return new_rtts_and_register_indices

def get_occupancies(thrift, args):
    occupancies = []
    current_timestamps = parse_thrift_register(run_thrift_cmd(thrift, 'register_read timestamps'))
    for i in range(args.num_tables):
        occupancy = len([t for t in current_timestamps[(i*args.table_size):((i+1)*args.table_size)] if t != 0])
        occupancies.append(occupancy)
    return occupancies

def main(args):
    rtts = []
    thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
    run_thrift_cmd(thrift, None) # Cue up the cmd line interface
    # Reset
    if args.reset:
        run_thrift_cmd(thrift, 'register_reset timestamps')
        run_thrift_cmd(thrift, 'register_reset keys')
        run_thrift_cmd(thrift, 'register_reset fourTupleMSS')
    # Initialize tuning parameters
    run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(args.initial_latency_threshold))
    run_thrift_cmd(thrift, 'register_write filter_percent 0 ' + str(args.initial_filter_percent))
    # Log file
    if args.log_file is not None:
        log_file = open(args.log_file, "w")
    while True:
        time.sleep(2)
        new_rtts_and_register_indices = get_new_rtts_and_register_indices(thrift, args)
        rtts.extend([rtt_and_register_index[0] for rtt_and_register_index in new_rtts_and_register_indices])
        if args.log_file is not None:
            for rtt_and_register_index in new_rtts_and_register_indices:
                log_file.write(str(rtt_and_register_index[0]) + "\n")
        occupancies = get_occupancies(thrift, args)
        # Check tunable parameters
        current_latency_threshold = parse_thrift_register(run_thrift_cmd(thrift, 'register_read latency_threshold'))[0]
        current_filter_percent = parse_thrift_register(run_thrift_cmd(thrift, 'register_read filter_percent'))[0]
        # Print statistics
        print "--------------------------------------"
        print "# pkts processed:              " + str(len(rtts))
        print "# pkts exceeding threshold:    " + str(len([rtt for rtt in rtts if rtt > args.rtt_threshold]))
        print "# pkts at or below threshold:  " + str(len([rtt for rtt in rtts if rtt <= args.rtt_threshold]))
        if len(rtts) > 0:
            print "Average RTT:                   " + str(sum(rtts) / len(rtts))
        if len(new_rtts_and_register_indices) > 0:
            print "New RTTs and register indices:",
            print new_rtts_and_register_indices
        print "Occupancies of registers:      " + str(sum(occupancies)),
        print occupancies
        print "Stale RTT threshold:           " + str(current_latency_threshold)
        print "Filter percent for sampling:   " + str(current_filter_percent)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Controller for RTT-P4')
    parser.add_argument('--sla', dest='rtt_threshold', type=int,
        action="store", required=True)
    parser.add_argument('--ts', dest='table_size', type=int,
        action="store", required=True)
    parser.add_argument('--nt', dest='num_tables', type=int,
        action="store", required=True)
    parser.add_argument('--stale', dest='initial_latency_threshold', type=int,
        action="store", required=False, default=500000)
    parser.add_argument('--filter', dest='initial_filter_percent', type=int,
        action="store", required=False, default=0)
    parser.add_argument('--max', dest='max_reportable_rtt', type=int,
        action="store", required=False, default=10000000)
    parser.add_argument('--file', dest='log_file', type=str,
        action="store", required=False, default=None)
    parser.add_argument('--reset', dest='reset',
        action="store_true", required=False)
    args = parser.parse_args()
    main(args)
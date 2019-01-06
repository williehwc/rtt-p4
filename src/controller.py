#!/usr/bin/env python2
import sys, time, pexpect, re

TABLE_SIZE = 5
NUM_TABLES = 4

INITIAL_LATENCY_THRESHOLD = 5000000

def run_thrift_command(thrift, command):
    if command is not None:
        thrift.sendline(command)
    thrift.expect('RuntimeCmd: ')
    return thrift.before

def parse_thrift_register(thrift_output):
    thrift_output_lines = thrift_output.splitlines()
    return [int(rtt_string) for rtt_string in re.findall(r'\d+', thrift_output)]

def main(rtt_threshold):
    rtts = []
    thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
    run_thrift_command(thrift, None) # Cue up the command line interface
    # Initialize tuning parameters
    run_thrift_command(thrift, 'register_write latency_threshold 0 ' + str(INITIAL_LATENCY_THRESHOLD))
    while True:
        time.sleep(2)
        # Issue read commands
        current_rtts_thrift_output = run_thrift_command(thrift, 'register_read rtts')
        current_register_indices_of_rtts_thrift_output = \
            run_thrift_command(thrift, 'register_read register_indices_of_rtts')
        current_timestamps_thrift_output = run_thrift_command(thrift, 'register_read timestamps')
        current_latency_threshold_thrift_output = run_thrift_command(thrift, 'register_read latency_threshold')
        # Issue reset commands
        run_thrift_command(thrift, 'register_reset rtts')
        run_thrift_command(thrift, 'register_reset register_indices_of_rtts')
        run_thrift_command(thrift, 'register_reset current_rtt_index')
        # Process new RTTs
        new_rtts_and_register_indices = []
        current_rtts = parse_thrift_register(current_rtts_thrift_output)
        current_register_indices_of_rtts = \
            parse_thrift_register(current_register_indices_of_rtts_thrift_output)
        for i in range(len(current_rtts)):
            if current_rtts[i] > 0 and current_register_indices_of_rtts[i] < TABLE_SIZE * NUM_TABLES:
               rtts.append(current_rtts[i])
               new_rtts_and_register_indices.append((current_rtts[i], current_register_indices_of_rtts[i]))
        # Check the occupancies of timestamp register
        current_timestamps = parse_thrift_register(current_timestamps_thrift_output)
        occupancies = []
        for i in range(NUM_TABLES):
            occupancy = len([t for t in current_timestamps[(i*TABLE_SIZE):((i+1)*TABLE_SIZE)] if t != 0])
            occupancies.append(occupancy)
        # Chceck tuning parameters
        current_latency_threshold = parse_thrift_register(current_latency_threshold_thrift_output)[0]
        # Print statistics
        print "--------------------------------------"
        print "# pkts processed:              " + str(len(rtts))
        print "# pkts exceeding threshold:    " + str(len([rtt for rtt in rtts if rtt > rtt_threshold]))
        print "# pkts at or below threshold:  " + str(len([rtt for rtt in rtts if rtt <= rtt_threshold]))
        if len(rtts) > 0:
            print "Average RTT:                   " + str(sum(rtts) / len(rtts))
        if len(new_rtts_and_register_indices) > 0:
            print "New RTTs and register indices:",
            print new_rtts_and_register_indices
        print "Occupancies of registers:      " + str(sum(occupancies)),
        print occupancies
        print "Stale RTT threshold:           " + str(current_latency_threshold)
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Pass 1 argument: <RTT threshold in microseconds>'
        exit(1)
    main(int(sys.argv[1]))
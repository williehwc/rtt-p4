#!/usr/bin/env python2
import sys, time, pexpect, re

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
    while True:
        time.sleep(2)
        # Issue commands
        current_rtts_thrift_output = run_thrift_command(thrift, 'register_read rtts')
        run_thrift_command(thrift, 'register_reset rtts')
        run_thrift_command(thrift, 'register_reset current_rtt_index')
        # Process new RTTs
        current_rtts = parse_thrift_register(current_rtts_thrift_output)
        for rtt in current_rtts:
            if rtt > 0:
               rtts.append(rtt)
        # Print statistics
        print "--------------------------------------"
        print "# pkts processed:             " + str(len(rtts))
        print "# pkts exceeding threshold:   " + str(len([rtt for rtt in rtts if rtt > rtt_threshold]))
        print "# pkts at or below threshold: " + str(len([rtt for rtt in rtts if rtt <= rtt_threshold]))
        if len(rtts) > 0:
            print "Average RTT:                  " + str(sum(rtts) / len(rtts))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Pass 1 argument: <RTT threshold in microseconds>'
        exit(1)
    main(int(sys.argv[1]))
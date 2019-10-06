#!/usr/bin/env python2

# Iterate over multiple target latencies (multiple times) and number of flows
# Perform this experiment twice: once for 4 tables, another for 1

import pexpect, time, signal, sys
from controller import run_thrift_cmd, parse_thrift_register, get_new_rtts_and_register_indices, get_occupancies
from argparse import Namespace

TARGET_LATENCIES = range(100000, 1100000, 200000)
NUMS_FLOWS = [1, 5, 10, 20] # red orange green blue
NUM_TRIALS = 10 # per target latency and num flows combo

STALE = 5000000
TABLE_SIZE = 1000
NUM_TABLES = 4
MAX_REPORTABLE_RTT = 10000000

ARGS = Namespace(table_size=TABLE_SIZE, num_tables=NUM_TABLES, max_reportable_rtt=MAX_REPORTABLE_RTT)

def run_mininet_cmd(mininet, cmd):
	mininet.expect('mininet> ')
	mininet.sendline(cmd)

def signal_handler(sig, frame):
	run_mininet_cmd(mininet, "exit")
	mininet.wait()
	sys.exit(0)

if __name__ == '__main__':

	# Mininet, then wait a while
	mininet = pexpect.spawn('make run')
	time.sleep(10)

	# Controller
	thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
	run_thrift_cmd(thrift, None) # Cue up the command line interface
	run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(STALE))

	signal.signal(signal.SIGINT, signal_handler)

	f = open("experiment1.txt", "w")

	for trial_no in range(NUM_TRIALS):
		for target_latency in TARGET_LATENCIES:
			for num_flows in NUMS_FLOWS:
				# Reset registers
				run_thrift_cmd(thrift, 'register_reset timestamps')
				run_thrift_cmd(thrift, 'register_reset keys')
				run_thrift_cmd(thrift, 'register_reset fourTupleMSS')
				print "--------------------------------------"
				print "TL " + str(target_latency) + " Flows " + str(num_flows) + " Trial " + str(trial_no)
				# Start the receive script
				run_mininet_cmd(mininet, "h2 ./receive.py -a " + str(target_latency / 1000000.) + \
					" -b " + str(target_latency / 1000000.) + " -r 1 -g f" + str(num_flows) + "_l" + \
					str(target_latency) + "_t" + str(trial_no) + "_r.txt &")
				# Wait a bit, then start the send script
				time.sleep(1)
				run_mininet_cmd(mininet, "h1 ./multisend.py " + str(num_flows) + " f" + str(num_flows) + "_l" + \
					str(target_latency) + "_t" + str(trial_no) + "_s.txt -t 100 -n 5 -m 10 -e .25 -k &")
				# Wait about a minute
				time.sleep(59)
				# Quit the send/receive scripts
				run_mininet_cmd(mininet, "h1 kill -SIGINT $!")
				run_mininet_cmd(mininet, "h2 kill -SIGINT $!")
				# Read RTTs
				new_rtts_and_register_indices = get_new_rtts_and_register_indices(thrift, ARGS)
				rtts = [rtt_and_register_index[0] for rtt_and_register_index in new_rtts_and_register_indices]
				occupancies = get_occupancies(thrift, ARGS)
				# Print statistics
				print "# pkts processed:              " + str(len(rtts))
				if len(rtts) > 0:
					print "Average RTT:                   " + str(sum(rtts) / len(rtts))
				if len(new_rtts_and_register_indices) > 0:
					print "Number of new RTTs:           ",
					print len(new_rtts_and_register_indices)
				print "Occupancies of registers:      " + str(sum(occupancies)),
				print occupancies
				# Write to file
				f.write(str(trial_no) + "," + str(target_latency) + "," + str(num_flows) + "," \
					+ str(sum(rtts) / len(rtts)) + "\n")

	signal_handler(None, None)
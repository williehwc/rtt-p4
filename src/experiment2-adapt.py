#!/usr/bin/env python2

import pexpect, time, signal, sys, os, re, math, functools
from controller import run_thrift_cmd, parse_thrift_register, get_new_rtts_and_register_indices, get_occupancies
from argparse import Namespace

# Parts I and II
MAX_REPORTABLE_RTT = 10000000
NUM_TRIALS = 10

# Part I
INITIAL_STALE = 200000
ADAPT_PERCENTILE = 0.95
NUM_TABLES = 4
TABLE_SIZE = 15
# stale, trial_no
PART_I_RECEIVER_CMD = "h2 ./receive.py -a 0.5 -b 0.5 -r 1 -g i%d_t%d_r.txt &"
PART_I_SENDER_CMD = "h1 ./multisend.py 5 i%d_t%d_s.txt -t 100 -n 5 -m 10 -e .25 -k &"
PART_I_WAIT_TIME = 1.95
PART_I_NUM_WAITS = 20

# Experiment 3 (Comment out if not using)
PART_I_RECEIVER_CMD = "h2 ./receive.py -a 0.3 -b 0.3 --aa 0.7 --bb 0.7 -v 0.5 -r 1 -g i%d_t%d_r.txt &"
PART_II_RECEIVER_CMD = "h2 ./receive.py -a 0.3 -b 0.3 --aa 0.7 --bb 0.7 -v 0.5 -r 1 -g ii%d_n%d_t%d_r.txt &"

def run_mininet_cmd(mininet, cmd):
	mininet.expect('mininet> ')
	mininet.sendline(cmd)

def signal_handler(sig, frame):
	run_mininet_cmd(mininet, "exit")
	mininet.wait()
	sys.exit(0)

def reset_registers(thrift):
	run_thrift_cmd(thrift, 'register_reset timestamps')
	run_thrift_cmd(thrift, 'register_reset keys')
	run_thrift_cmd(thrift, 'register_reset fourTupleMSS')

def quit_mininet_bg_jobs(mininet):
	run_mininet_cmd(mininet, "h1 kill -SIGINT $!")
	run_mininet_cmd(mininet, "h2 kill -SIGINT $!")

def set_table_size_and_num_tables(table_size, num_tables):
	# Read program file
	program_file = open('program.p4', 'r')
	program_content = program_file.read()
	program_content = re.sub(r'const bit<32> TABLE_SIZE = \d+;',
							 'const bit<32> TABLE_SIZE = ' + str(table_size) + ';',
							 program_content, flags=re.M)
	program_content = re.sub(r'#define MULTI_TABLE \d+',
							 '#define MULTI_TABLE ' + str(num_tables),
							 program_content, flags=re.M)
	program_file.close()
	# Write modified program file
	program_file = open('program.p4', 'w')
	program_file.write(program_content)
	program_file.close()

def print_statistics(rtts, occupancies):
	print "# pkts processed:              " + str(len(rtts))
	if len(rtts) > 0:
		print "Average RTT:                   " + str(sum(rtts) / len(rtts))
	print "Occupancies of registers:      " + str(sum(occupancies)),
	print occupancies

## {{{ http://code.activestate.com/recipes/511478/ (r1)
def percentile(N, percent, key=lambda x:x):
    """
    Find the percentile of a list of values.

    @parameter N - is a list of values. Note N MUST BE already sorted.
    @parameter percent - a float value from 0.0 to 1.0.
    @parameter key - optional key function to compute value from each element of N.

    @return - the percentile of the values
    """
    if not N:
        return None
    k = (len(N)-1) * percent
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return key(N[int(k)])
    d0 = key(N[int(f)]) * (c-k)
    d1 = key(N[int(c)]) * (k-f)
    return d0+d1

def adapt_stale(args, thrift):
	rtts = []
	current_rtts_thrift_output = run_thrift_cmd(thrift, 'register_read rtts')
	current_register_indices_of_rtts_thrift_output = \
        run_thrift_cmd(thrift, 'register_read register_indices_of_rtts')
	current_rtts = parse_thrift_register(current_rtts_thrift_output)
	current_register_indices_of_rtts = \
		parse_thrift_register(current_register_indices_of_rtts_thrift_output)
	for i in range(len(current_rtts)):
		if current_rtts[i] > 0 and current_register_indices_of_rtts[i] < args.table_size * args.num_tables \
			and current_rtts[i] <= args.max_reportable_rtt:
			rtts.append(current_rtts[i])
	rtts.sort()
	try:
		new_stale = int(percentile(rtts, ADAPT_PERCENTILE))
		print ">>>>>>> Stale: " + str(new_stale) + " calculated from " + str(len(rtts)) + " RTT(s)"
		run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(new_stale))
	except:
		print ">>>>>>> No RTTs yet"

def part_i(f):

	set_table_size_and_num_tables(TABLE_SIZE, NUM_TABLES)

	# Mininet, then wait a while
	mininet = pexpect.spawn('make run')
	time.sleep(10)

	# Controller
	thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
	run_thrift_cmd(thrift, None) # Cue up the command line interface

	# Args
	args = Namespace(table_size=TABLE_SIZE, num_tables=NUM_TABLES, max_reportable_rtt=MAX_REPORTABLE_RTT)

	run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(2000000))
	for trial_no in range(NUM_TRIALS):
		reset_registers(thrift)
		print "--------------------------------------"
		print "STALE " + str(INITIAL_STALE) + " trial " + str(trial_no)
		# Start the receive script
		run_mininet_cmd(mininet, PART_I_RECEIVER_CMD % (2000000, trial_no))
		# Wait a bit, then start the send script
		time.sleep(1)
		run_mininet_cmd(mininet, PART_I_SENDER_CMD % (2000000, trial_no))
		# Wait
		for i in range(PART_I_NUM_WAITS):
			time.sleep(PART_I_WAIT_TIME)
			adapt_stale(args, thrift)
		# Quit the send/receive scripts
		quit_mininet_bg_jobs(mininet)
		# Read RTTs
		new_rtts_and_register_indices = get_new_rtts_and_register_indices(thrift, args)
		rtts = [rtt_and_register_index[0] for rtt_and_register_index in new_rtts_and_register_indices]
		occupancies = get_occupancies(thrift, args)
		# Print statistics
		print_statistics(rtts, occupancies)
		# Write to file
		f.write("i\t" + str(2000000) + "\t" + str(trial_no) + "\t" + ",".join(map(str, rtts)) + "\n")

	thrift.close()
	run_mininet_cmd(mininet, "exit")
	mininet.wait()
	os.system("make clean")

if __name__ == '__main__':
	f = open("experiment2-adapt.tsv", "w")
	part_i(f)
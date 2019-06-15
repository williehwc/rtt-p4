#!/usr/bin/env python2

import pexpect, time, signal, sys, os, re
from controller import run_thrift_cmd, parse_thrift_register, get_new_rtts_and_register_indices, get_occupancies
from argparse import Namespace

# Parts I and II
MAX_REPORTABLE_RTT = 10000000
NUM_TRIALS = 10

# Part I
RUN_PART_I = False
STALES = [200000, 400000, 600000, 800000, 1000000, 1200000, 1400000, 1600000]
NUM_TABLES = 4
TABLE_SIZE = 15
# stale, trial_no
PART_I_RECEIVER_CMD = "h2 ./receive.py -a 0.5 -b 0.5 -r 1 -g i%d_t%d_r.txt &"
PART_I_SENDER_CMD = "h1 ./multisend.py 5 i%d_t%d_s.txt -t 100 -n 5 -m 10 -e .25 -k &"
PART_I_WAIT_TIME = 39

# Part II
RUN_PART_II = True
STALE = 1000000
TABLE_SIZES_AND_NUMS_TABLES =  [(30, 2), (60, 2), (90, 2), (120,2)]
# table_size, num_tables, trial_no
PART_II_RECEIVER_CMD = "h2 ./receive.py -a 0.5 -b 0.5 -r 1 -g ii%d_n%d_t%d_r.txt &"
PART_II_SENDER_CMD = "h1 ./multisend.py 5 ii%d_n%d_t%d_s.txt -t 100 -n 5 -m 10 -e .25 -k &"
PART_II_WAIT_TIME = 39

# Experiment 3 (Comment out if not using)
#RUN_PART_I = True
#RUN_PART_II = False
#PART_I_RECEIVER_CMD = "h2 ./receive.py -a 0.3 -b 0.3 --aa 0.7 --bb 0.7 -v 0.5 -r 1 -g i%d_t%d_r.txt &"
#PART_II_RECEIVER_CMD = "h2 ./receive.py -a 0.3 -b 0.3 --aa 0.7 --bb 0.7 -v 0.5 -r 1 -g ii%d_n%d_t%d_r.txt &"

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

# Part I: Vary stale timeout
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

	for stale in STALES:
		run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(stale))
		for trial_no in range(NUM_TRIALS):
			reset_registers(thrift)
			print "--------------------------------------"
			print "STALE " + str(stale) + " trial " + str(trial_no)
			# Start the receive script
			run_mininet_cmd(mininet, PART_I_RECEIVER_CMD % (stale, trial_no))
			# Wait a bit, then start the send script
			time.sleep(1)
			run_mininet_cmd(mininet, PART_I_SENDER_CMD % (stale, trial_no))
			# Wait
			time.sleep(PART_I_WAIT_TIME)
			# Quit the send/receive scripts
			quit_mininet_bg_jobs(mininet)
			# Read RTTs
			new_rtts_and_register_indices = get_new_rtts_and_register_indices(thrift, args)
			rtts = [rtt_and_register_index[0] for rtt_and_register_index in new_rtts_and_register_indices]
			occupancies = get_occupancies(thrift, args)
			# Print statistics
			print_statistics(rtts, occupancies)
			# Write to file
			f.write("i\t" + str(stale) + "\t" + str(trial_no) + "\t" + ",".join(map(str, rtts)) + "\n")

	thrift.close()
	run_mininet_cmd(mininet, "exit")
	mininet.wait()
	os.system("make clean")

# Part II: Vary number of entries per table and number of tables
def part_ii(f):

	for table_size_and_num_tables in TABLE_SIZES_AND_NUMS_TABLES:
		table_size = table_size_and_num_tables[0]
		num_tables = table_size_and_num_tables[1]

		set_table_size_and_num_tables(table_size, num_tables)

		# Mininet, then wait a while
		mininet = pexpect.spawn('make run')
		time.sleep(10)

		# Controller
		thrift = pexpect.spawn('python ../utils/runtime_CLI.py')
		run_thrift_cmd(thrift, None) # Cue up the command line interface

		# Args
		args = Namespace(table_size=table_size, num_tables=num_tables, max_reportable_rtt=MAX_REPORTABLE_RTT)

		run_thrift_cmd(thrift, 'register_write latency_threshold 0 ' + str(STALE))

		for trial_no in range(NUM_TRIALS):
			reset_registers(thrift)
			print "--------------------------------------"
			print "SIZE " + str(table_size) + ", " + str(num_tables) + ", trial " + str(trial_no)
			# Start the receive script
			run_mininet_cmd(mininet, PART_II_RECEIVER_CMD % (table_size, num_tables, trial_no))
			# Wait a bit, then start the send script
			time.sleep(1)
			run_mininet_cmd(mininet, PART_II_SENDER_CMD % (table_size, num_tables, trial_no))
			# Wait
			time.sleep(PART_II_WAIT_TIME)
			# Quit the send/receive scripts
			quit_mininet_bg_jobs(mininet)
			# Read RTTs
			new_rtts_and_register_indices = get_new_rtts_and_register_indices(thrift, args)
			rtts = [rtt_and_register_index[0] for rtt_and_register_index in new_rtts_and_register_indices]
			occupancies = get_occupancies(thrift, args)
			# Print statistics
			print_statistics(rtts, occupancies)
			# Write to file
			f.write("ii\t" + str(table_size) + "\t" + str(num_tables) + "\t" + str(trial_no) + \
				"\t" + ",".join(map(str, rtts)) + "\n")

		thrift.close()
		run_mininet_cmd(mininet, "exit")
		mininet.wait()
		os.system("make clean")

if __name__ == '__main__':
	f = open("experiment2.tsv", "w")
	if RUN_PART_I:
		part_i(f)
	if RUN_PART_II:
		part_ii(f)
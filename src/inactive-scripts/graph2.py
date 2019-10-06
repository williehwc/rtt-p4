# 1 boxplot: Stale vs percentage of RTTs over SLA (.5 sec)

import re
import matplotlib.pyplot as plt

TRIALS = range(10)
SLA = 0.5
NUM_FLOWS = 5

# Part I: Stale
I_DIRECTORY = "experiment2i-15tblsz/"
STALES_IN_MICROSEC = [200000, 400000, 600000, 800000, 1000000, 1200000, 1400000, 1600000, 2000000]
MAX_STALE_POINT = 2.2

# Part II and III: Table size and number of tables
II_III_DIRECTORY = "experiment2ii-1000msstale/"
II_TABLE_SIZES_AND_NUMS_TABLES =  [(30, 2), (60, 2), (90, 2), (120,2)]
III_TABLE_SIZES_AND_NUMS_TABLES = [(60, 1), (30, 2), (20, 3), (15, 4)]

rtts_dict = dict()

# Part I: Read experiment2.tsv
f = open(I_DIRECTORY + "experiment2.tsv")
f_lines = f.readlines()
for f_line in f_lines:
	f_line_search = re.search("i\t(?P<key>\d+\t\d+)\t(?P<rtts_microsec_str>[\d,]+)", f_line)
	rtts_dict[f_line_search.group("key")] = \
		[float(r) / 1000000 for r in f_line_search.group("rtts_microsec_str").split(",")]
f.close()

# Part II and III: Read experiment2.tsv
f = open(II_III_DIRECTORY + "experiment2.tsv")
f_lines = f.readlines()
for f_line in f_lines:
	f_line_search = re.search("i\t(?P<key>\d+\t\d+\t\d+)\t(?P<rtts_microsec_str>[\d,]+)", f_line)
	rtts_dict[f_line_search.group("key")] = \
		[float(r) / 1000000 for r in f_line_search.group("rtts_microsec_str").split(",")]
f.close()

all_i_receiver_latencies = []
all_i_sender_latencies = []
all_i_num_rtts = []
all_i_average_rtts = []
all_i_sla_violation_rate = []

all_ii_receiver_latencies = []
all_ii_sender_latencies = []
all_ii_num_rtts = []
all_ii_average_rtts = []
all_ii_sla_violation_rate = []

all_iii_receiver_latencies = []
all_iii_sender_latencies = []
all_iii_num_rtts = []
all_iii_average_rtts = []
all_iii_sla_violation_rate = []

# Part I: Go through the other files
for stale_in_microsec in STALES_IN_MICROSEC:

	receiver_latencies = []
	sender_latencies = []
	num_rtts = []
	average_rtts = []
	sla_violation_rates = []

	for trial_no in TRIALS:

		# Receiver latency
		f = open(I_DIRECTORY + "i%d_t%d_r.txt" % (stale_in_microsec, trial_no))
		receiver_latencies.append(float(f.read()))
		f.close()

		# Sender latency
		individual_sender_latencies = []
		for flow_no in range(NUM_FLOWS):
			f = open(I_DIRECTORY + "%d_i%d_t%d_s.txt" % (flow_no, stale_in_microsec, trial_no))
			individual_sender_latencies.append(float(f.read()))
			f.close()
		sender_latencies.append(sum(individual_sender_latencies) / len(individual_sender_latencies))

		# RTTs
		rtts = rtts_dict["%d\t%d" % (stale_in_microsec, trial_no)]
		num_rtts.append(len(rtts))
		average_rtts.append(sum(rtts) / len(rtts))
		sla_violation_rates.append(len([r for r in rtts if r > SLA]) / len(rtts))

	all_i_receiver_latencies.append(receiver_latencies)
	all_i_sender_latencies.append(sender_latencies)
	all_i_num_rtts.append(num_rtts)
	all_i_average_rtts.append(average_rtts)
	all_i_sla_violation_rate.append(sla_violation_rates)

# Part II: Go through the other files
for table_size_and_num_tables in II_TABLE_SIZES_AND_NUMS_TABLES:

	table_size = table_size_and_num_tables[0]
	num_tables = table_size_and_num_tables[1]

	receiver_latencies = []
	sender_latencies = []
	num_rtts = []
	average_rtts = []
	sla_violation_rates = []

	for trial_no in TRIALS:

		# Receiver latency
		f = open(II_III_DIRECTORY + "ii%d_n%d_t%d_r.txt" % (table_size, num_tables, trial_no))
		receiver_latencies.append(float(f.read()))
		f.close()

		# Sender latency
		individual_sender_latencies = []
		for flow_no in range(NUM_FLOWS):
			f = open(II_III_DIRECTORY + "%d_ii%d_n%d_t%d_s.txt" % (flow_no, table_size, num_tables, trial_no))
			individual_sender_latencies.append(float(f.read()))
			f.close()
		sender_latencies.append(sum(individual_sender_latencies) / len(individual_sender_latencies))

		# RTTs
		rtts = rtts_dict["%d\t%d\t%d" % (table_size, num_tables, trial_no)]
		num_rtts.append(len(rtts))
		average_rtts.append(sum(rtts) / len(rtts))
		sla_violation_rates.append(len([r for r in rtts if r > SLA]) / len(rtts))

	all_ii_receiver_latencies.append(receiver_latencies)
	all_ii_sender_latencies.append(sender_latencies)
	all_ii_num_rtts.append(num_rtts)
	all_ii_average_rtts.append(average_rtts)
	all_ii_sla_violation_rate.append(sla_violation_rates)

# Part III: Go through the other files
for table_size_and_num_tables in III_TABLE_SIZES_AND_NUMS_TABLES:

	table_size = table_size_and_num_tables[0]
	num_tables = table_size_and_num_tables[1]

	receiver_latencies = []
	sender_latencies = []
	num_rtts = []
	average_rtts = []
	sla_violation_rates = []

	for trial_no in TRIALS:

		# Receiver latency
		f = open(II_III_DIRECTORY + "ii%d_n%d_t%d_r.txt" % (table_size, num_tables, trial_no))
		receiver_latencies.append(float(f.read()))
		f.close()

		# Sender latency
		individual_sender_latencies = []
		for flow_no in range(NUM_FLOWS):
			f = open(II_III_DIRECTORY + "%d_ii%d_n%d_t%d_s.txt" % (flow_no, table_size, num_tables, trial_no))
			individual_sender_latencies.append(float(f.read()))
			f.close()
		sender_latencies.append(sum(individual_sender_latencies) / len(individual_sender_latencies))

		# RTTs
		rtts = rtts_dict["%d\t%d\t%d" % (table_size, num_tables, trial_no)]
		num_rtts.append(len(rtts))
		average_rtts.append(sum(rtts) / len(rtts))
		sla_violation_rates.append(len([r for r in rtts if r > SLA]) / len(rtts))

	all_iii_receiver_latencies.append(receiver_latencies)
	all_iii_sender_latencies.append(sender_latencies)
	all_iii_num_rtts.append(num_rtts)
	all_iii_average_rtts.append(average_rtts)
	all_iii_sla_violation_rate.append(sla_violation_rates)

# Make figure
fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6), sharey=True)
fig.subplots_adjust(wspace=0)

ax1.boxplot(
	all_i_num_rtts,
	positions=[s / 1000000 for s in STALES_IN_MICROSEC],
    widths=.1
)
ax1.set_xlim((0, MAX_STALE_POINT))
ax1.set_xlabel("Stale threshold (s)")
ax1.set_ylabel("Number of RTTs recorded by switch")

ax2.boxplot(
	all_ii_num_rtts,
	positions=range(len(II_TABLE_SIZES_AND_NUMS_TABLES)),
    widths=.5
)
ax2.set_xlabel("Table size × Number of tables")
ax2.set_xticklabels(["%d × %d" % (x[0], x[1]) for x in II_TABLE_SIZES_AND_NUMS_TABLES])

ax3.boxplot(
	all_iii_num_rtts,
	positions=range(len(III_TABLE_SIZES_AND_NUMS_TABLES)),
    widths=.5
)
ax3.set_xlabel("Table size × Number of tables")
ax3.set_xticklabels(["%d × %d" % (x[0], x[1]) for x in III_TABLE_SIZES_AND_NUMS_TABLES])

fig.savefig("graph2.png", dpi=300)
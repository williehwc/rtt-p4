# 1 boxplot: Stale vs percentage of RTTs over SLA (.5 sec)

import re
import matplotlib.pyplot as plt

DIRECTORY = "experiment3i-15tblsz/"
TRIALS = range(10)
STALES_IN_MICROSEC = [200000, 400000, 600000, 800000, 1000000, 1200000, 1400000, 1600000, 2000000]
SLA = 0.5
NUM_FLOWS = 5
MAX_STALE_POINT = 2.2

# Read experiment2.tsv
rtts_dict = dict()
f = open(DIRECTORY + "experiment2.tsv")
f_lines = f.readlines()
for f_line in f_lines:
	f_line_search = re.search("i\t(?P<key>\d+\t\d+)\t(?P<rtts_microsec_str>[\d,]+)", f_line)
	rtts_dict[f_line_search.group("key")] = \
		[float(r) / 1000000 for r in f_line_search.group("rtts_microsec_str").split(",")]
f.close()

all_sender_latencies = []
all_num_rtts = []
all_average_rtts = []
all_sla_violation_rate = []

# Go through the other files
for stale_in_microsec in STALES_IN_MICROSEC:

	sender_latencies = []
	num_rtts = []
	average_rtts = []
	sla_violation_rates = []

	for trial_no in TRIALS:

		# Sender latency
		individual_sender_latencies = []
		for flow_no in range(NUM_FLOWS):
			f = open(DIRECTORY + "%d_i%d_t%d_s.txt" % (flow_no, stale_in_microsec, trial_no))
			individual_sender_latencies.append(float(f.read()))
			f.close()
		sender_latencies.append(sum(individual_sender_latencies) / len(individual_sender_latencies))

		# RTTs
		rtts = rtts_dict["%d\t%d" % (stale_in_microsec, trial_no)]
		num_rtts.append(len(rtts))
		average_rtts.append(sum(rtts) / len(rtts))
		sla_violation_rates.append(len([r for r in rtts if r > SLA]) / len(rtts))

	all_sender_latencies.append(sender_latencies)
	all_num_rtts.append(num_rtts)
	all_average_rtts.append(average_rtts)
	all_sla_violation_rate.append(sla_violation_rates)

# Make figure
fig, ax = plt.subplots(figsize=(8, 6))

ax.boxplot(
	all_sla_violation_rate,
	positions=[s / 1000000 for s in STALES_IN_MICROSEC],
    widths=.1
)
ax.set_xlim((0, MAX_STALE_POINT))
ax.set_xlabel("Stale threshold (s)")
ax.set_ylabel("Fraction of RTTs exceeding 0.5 s")
ax.plot([0, MAX_STALE_POINT], [0.5, 0.5], color='#CCCCCC', linestyle='-', linewidth=1)

fig.savefig("graph3i.png", dpi=300)
# 2 scatterplots: (1) Target latency vs sender latency
#                 (2) Target latency vs RTT

import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

DIRECTORY = "experiment1-4tbl/"
TRIALS = [0,1,2,5,6,7,8,9] # 3 and 4 were tainted b/c I was using computer during those trials
TARGET_LATENCIES_MICROSEC = range(100000, 1100000, 200000)
NUMS_FLOWS = [1, 5, 10]
COLORS = ["orange", "blue", "green"]
MAX_RTT_POINT = 1.2

# Target latencies for plotting
target_latencies_for_plotting = []
for target_latency_microsec in TARGET_LATENCIES_MICROSEC:
	for trial_no in TRIALS:
		target_latencies_for_plotting.append(target_latency_microsec / 1000000.)

# Read experiment1.txt
rtts_dict = dict()
f = open(DIRECTORY + "experiment1.txt")
f_lines = f.readlines()
for f_line in f_lines:
	f_line_search = re.search("(?P<key>\d+,\d+,\d+),(?P<rtt_microsec>\d+)", f_line)
	rtts_dict[f_line_search.group("key")] = float(f_line_search.group("rtt_microsec")) / 1000000
f.close()

# Make figure
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

# Go through the other files
for i in reversed(range(len(NUMS_FLOWS))):
	num_flows = NUMS_FLOWS[i]

	receiver_latencies = []
	sender_latencies = []
	rtts = []

	for target_latency_microsec in TARGET_LATENCIES_MICROSEC:

		for trial_no in TRIALS:

			# Receiver latency
			f = open(DIRECTORY + "f%d_l%d_t%d_r.txt" % (num_flows, target_latency_microsec, trial_no))
			receiver_latencies.append(float(f.read()))
			f.close()

			# Sender latency
			individual_sender_latencies = []
			for flow_no in range(num_flows):
				f = open(DIRECTORY + "%d_f%d_l%d_t%d_s.txt" % (flow_no, num_flows, target_latency_microsec, trial_no))
				individual_sender_latencies.append(float(f.read()))
				f.close()
			sender_latencies.append(sum(individual_sender_latencies) / len(individual_sender_latencies))

			# RTT
			rtts.append(rtts_dict["%d,%d,%d" % (trial_no, target_latency_microsec, num_flows)])

	# Plot this num_flows
	color = COLORS[i]
	ax1.scatter(target_latencies_for_plotting, sender_latencies, s=10, c=color)
	ax1.set_xlabel("Target latencies (s)")
	ax1.set_ylabel("Average RTTs observed by sender (s)")
	ax1.set_xlim((0, MAX_RTT_POINT))
	ax1.set_ylim((0, MAX_RTT_POINT))
	ax1.plot([0, MAX_RTT_POINT], [0, MAX_RTT_POINT], color='#CCCCCC', linestyle='-', linewidth=1)
	ax2.scatter(sender_latencies, rtts, s=10, c=color)
	ax2.set_xlabel("Average RTTs observed by sender (s)")
	ax2.set_ylabel("Average RTTs recorded by switch (s)")
	ax2.set_xlim((0, MAX_RTT_POINT))
	ax2.set_ylim((0, MAX_RTT_POINT))
	ax2.plot([0, MAX_RTT_POINT], [0, MAX_RTT_POINT], color='#CCCCCC', linestyle='-', linewidth=1)

plt.legend(handles=[mpatches.Patch(color=COLORS[i], label="%d flows" % NUMS_FLOWS[i]) for i in range(len(NUMS_FLOWS))])

fig.savefig("graph1.png", dpi=300)
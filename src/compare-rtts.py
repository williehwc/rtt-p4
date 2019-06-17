# Read two CSVs of RTTs, actual and observed, and evaluate the latter
# Usage: python3 compare-rtts.py path/to/actual.csv path/to/observed.csv 0.1
# Note: Replace 0.1 with the replay speed. Assume 1 if omitted.
# Assumption: observed RTTs (calculated by the P4 switch) are integers
# Generates a "*.marked.csv" file, which adds a column at the end for RTT error.
# Prints results. "Bogus" refers to spurious observed RTTs. "MSE" is mean sq. error

import sys, csv, numpy

actual_filename = sys.argv[1]
observed_filename = sys.argv[2]

replay_speed = 1
if len(sys.argv) > 3:
    replay_speed = float(sys.argv[3])

# Read observed CSV
observed_rtts = dict()
num_observed_rtts = 0
with open(observed_filename) as observed_file:
    csv_reader = csv.reader(observed_file, delimiter=',')
    for row in csv_reader:
        if row[-1] == "0" or row[-2] == "0":
            continue
        key = ",".join(row[2:8])
        rtt = int(row[0])
        register_index_of_rtt = int(row[1])
        if key in observed_rtts:
            observed_rtts[key].append((rtt, register_index_of_rtt))
        else:
            observed_rtts[key] = [(rtt, register_index_of_rtt)]
        num_observed_rtts += 1

# Iterate over actual CSV
missed_rows = []
errors = []
num_actual_rtts = 0
with open(actual_filename + ".marked.csv", "w") as marked_actual_file:
    with open(actual_filename) as actual_file:
        csv_reader = csv.reader(actual_file, delimiter=',')
        for row in csv_reader:
            key = ",".join(row[2:8])
            actual_rtt = float(row[0])
            marked_actual_file.write(",".join(row) + ",")
            if key in observed_rtts and len(observed_rtts[key]) > 0:
                best_error = float("inf")
                index_of_rtt_with_best_error = -1
                for index, rtt_and_register_index_of_rtt in enumerate(observed_rtts[key]):
                    if abs(rtt_and_register_index_of_rtt[0] - actual_rtt) < abs(best_error):
                        best_error = rtt_and_register_index_of_rtt[0] - actual_rtt
                        index_of_rtt_with_best_error = index
                del observed_rtts[key][index_of_rtt_with_best_error]
                marked_actual_file.write(str(best_error))
                errors.append(best_error)
            else:
                missed_rows.append(",".join(row))
            marked_actual_file.write("\n")
            num_actual_rtts += 1

# Get all bogus RTTs
bogus_rows = []
for key, rtts_and_register_indices_of_rtt in observed_rtts.items():
    for rtt_and_register_index_of_rtt in rtts_and_register_indices_of_rtt:
        bogus_rows.append("%d,%d,%s" % (
            rtt_and_register_index_of_rtt[0],
            rtt_and_register_index_of_rtt[1], 
            key
        ))

# Print statistics: miss rate, bogus rate, observed count, MSE, bogus rows
print("Miss rate: %f (%d out of %d actual)" % (
    len(missed_rows) / float(num_actual_rtts),
    len(missed_rows),
    num_actual_rtts
))
print("Bogus rate: %f (%d out of %d observed)" % (
    len(bogus_rows) / float(num_observed_rtts),
    len(bogus_rows),
    num_observed_rtts
))
print("MSE: %f" % (numpy.array(errors) ** 2).mean())
print("Speed-adjusted MSE: %f" % ((numpy.array(errors) * replay_speed) ** 2).mean())
if len(bogus_rows) > 0:
    print("Bogus rows:")
    for bogus_row in bogus_rows:
        print(bogus_row)
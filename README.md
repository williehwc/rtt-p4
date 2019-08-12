# Behavioral Model Experiment Procedure

*B* can be completed independently of *A* steps. *C* must be completed after all other steps.

A1) In the VM, start the switch with `make run`.

A2) Open h1's terminal with `xterm h1` in Mininet.

A3) Start the controller with `./controller.py -r > observed_rtts_filename.csv` in another VM terminal.

A4) Wait a few seconds, then run `tcpreplay -x 0.1 -i "h1-eth0" pcap_filename.pcap` in h1's terminal.

A5) Wait for the replay to complete, then CTRL+C out of controller.py

B) Run `python3 pcap-rtt-stats.py pcap_filename.pcap 0.1` to generate the actual RTTs CSV.

C) Run `python3 compare-rtts.py pcap_filename.pcap.rtts.csv observed_rtts_filename.csv 0.1` to generate the marked actual RTTs CSV and print out results.

**Note**: In the examples above, 0.1 is the replay speed. Along with PCAP and CSV filenames, it can be changed, but remember to be consistent!

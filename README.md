# Pentagon_Wireshark
## Wireshark Simulator (Packet Sniffer)

Wireshark is one of the best packet analyzer programs, many network engineers use it in order to solve communication issues.

This Project is implementing a program similar to Wireshark, that can sniff inbound packets and save and load packets data
into "*.pcap" files, so we can analyze saved packets from Wireshark and take our sniffed packets for further inspection in Wireshark,
We can also add filters to the sniffing process to choose the packets that we want to analyze depending on a specific critera


## Dependencies

* This Project is implemented using <b>Python-3</b> so all the source code is <b>".py"</b> format
 using <b>"main.py"</b> to run th complete project
 
 * This Project is using the <b>QT Framework</b> for the GUI implementation, it's using version <b>PyQt5</b>.
 It can be installed from the Python Package Index (PYPI), However it comes already installed with Anaconda3.
 
 * This Project is implemented using </b>Scapy-Python3 (A.K.A Scapy3k) </b> for packet sniffing and analyzing.
 It can be installed by following the instructions in the Scapy-Python3 [GitHub Repository](https://github.com/phaethon/scapy).


## Features

* GUI to represent (Summary/Detailed/Hex) views for any packet in the current session
* Sniffing Mode
* Thradding to keep program responsive during the sniffing process
* Adding filters to the sniffing process
* Loadig data from a pcap file
* Saving current session into a pcap file
* Starting many sniffing sessions (can have different filters) and even starting new fresh sessions  in the same program instance
* Full Screen Mode

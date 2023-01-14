# PCAP-Analyser

## Table of Contents:
* [Introduction](#introduction)
* [Libraries used](#libraries-used)
* [Run the project](#run-the-project)
* [Analysis](#analysis)
* [Reference](#reference)

## Introduction:
PCAP is a file format used to capture packets going on the wire. When you exchange packets between A and B, most modern OSes will let you capture the packets that enter and leave the NIC. 

A PCAP library is available to parse the files. TCPdump is a command line tool to capture PCACP files. Wireshark is a similar tool that has a GUI; Wireshark can also be used to analyze the PCAP files.

In this project, we develop our own PCAP Analysis tool. We use this tool to analyse the TCP flows in our PCAP file. 

We also build an enhanced version of this tool that can analyse HTTP, along with TCP. 

## Libraries used
* [dpkt](https://pypi.org/project/dpkt/)
* [struct](https://docs.python.org/3/library/struct.html)


## Run the project

From the command line, run:


```bash
# Clone this repository
$ git clone https://github.com/parthskansara/PCAP-Analyser

# Go into the repository
$ cd PCAP-Analyser

# Install dependencies
$ pip install -r requirements.txt

```


To run the PCAP Analyser for TCP Flows, run the following command. It will prompt you to upload your PCAP file. Here's a [sample file](https://github.com/parthskansara/PCAP-Analyser/blob/main/Sample%20PCAP%20files/sample-tcp-pcap.pcap).

```bash
# Run the PCAP Analyser (for TCP Flows)
$ python pcap-analyser-tcp.py

```


To run the PCAP Analyser for HTTP Flows, run the following command. Here are the files we used [HTTP 1.0](https://github.com/parthskansara/PCAP-Analyser/blob/main/Sample%20PCAP%20files/sample-http-1080-pcap.pcap) [HTTP 1.1](https://github.com/parthskansara/PCAP-Analyser/blob/main/Sample%20PCAP%20files/sample-tcp-1081-pcap.pcap) [HTTP 2.0](https://github.com/parthskansara/PCAP-Analyser/blob/main/Sample%20PCAP%20files/sample-tcp-1082-pcap.pcap).


```bash
# Run the PCAP Analyser (for HTTP Flows)
$ python pcap-analyser-http.py

```


## Analysis
1. This [document](https://github.com/parthskansara/PCAP-Analyser/blob/main/docs/PCAP%20Analyser%20-%20TCP%20Flows.pdf) explains how our tool can be used to analyse the PCAP files for the following information about TCP flows:
* Number of TCP flows
* Transaction details for each flow
* Throughput, loss rate, average RTT and theoretical throughput for each flow

2. This [document](https://github.com/parthskansara/PCAP-Analyser/blob/main/docs/PCAP%20Analyser%20-%20TCP%20Flows%20(Congestion%20Control).pdf) explains how our tool can be used to analyse the PCAP files for the following information on Congestion Control in the captured TCP flows:
* Congestion Window size
* Number of retransmitted packets
  * Count of packets retransmitted due to Triple Duplicate ACK
  * Count of packets retransmitted due to Packet Loss
  
3. This [document](https://github.com/parthskansara/PCAP-Analyser/blob/main/docs/PCAP%20Analyser%20-%20HTTP%20Flows.pdf) explains how our enhanced tool can be used to analyse the PCAP files for the following information about HTTP flows:
* Reassembled unique HTTP requests/responses and the unique TCP tuple for all TCP segments ([see this](https://github.com/parthskansara/PCAP-Analyser/blob/main/docs/Reassembled%20HTTP%20flows.txt))
* Identify the version of HTTP used (1.0, 1.1 or 2.0)
* Load times for each HTTP flow
* Number of packets and raw bytes sent over each HTTP flow

## Reference
This project was completed as a part of the course CSE 534: Fundamentals of Computer Vision (Fall 2022) under [Prof. Aruna Balasubramanian](https://www.cs.stonybrook.edu/people/faculty/ArunaBalasubramanian) at Stony Brook University.


The original assignment can be found [here](https://drive.google.com/file/d/1OiIf7O8UnBkfdO672QrWKvyXfWAiedUl/view?usp=sharing).

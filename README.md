# Operation PACKET STORM

## Overview

This tool processes a pcap file containing network packets to analyse and extract various statistics. It computes the average packet size, total volume of data, most frequent destination IP, and the total number of packets broken down by transport layer protocol. The program is written in C++ and uses the `libpcap` library for packet analysis.

## Requirements

- C++17 or later
- `libpcap` development libraries

## Installation

### Installing `libpcap`

#### On Debian-based systems (Ubuntu, etc.)

```sh
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install libpcap-dev
```

#### On Red Hat-based systems (CentOS, Fedora, etc.)

```sh
sudo yum install libpcap-devel
```

#### On macOS (using Homebrew)

```sh
brew install libpcap
```

### Cloning the Repository

```sh
git clone https://github.com/njansari/packet-storm.git
cd packet-storm
```

## Building the Project

### Using g++

```sh
g++ -std=c++17 -o pcap_stats pcap_stats.cpp -lpcap
```

## Running the Binary

```sh
./pcap_stats /path/to/pcap/file
```

### Example

```sh
./pcap_stats packet-storm.pcap
```

## Output

The program will output the following statistics:

- Total number of packets
- Total volume of data transmitted
- Average packet size
- Maximum packet size
- Number of TCP packets
- Number of UDP packets
- Most frequent source IPs
- Most frequent destination IPs
- Number of malformed packets detected

### Sample Output

```
Total number of packets: 1000000
Total volume of data: 500000000 bytes

Average packet size: 500 bytes
Maximum packet size: 1500 bytes

TCP packets: 800000
UDP packets: 200000

Most Frequent Source IPs:
1) 192.168.1.1 - 100000 packets
2) 192.168.1.2 - 90000 packets
3) 192.168.1.3 - 80000 packets
4) 192.168.1.4 - 70000 packets
5) 192.168.1.5 - 60000 packets

Most Frequent Destination IPs:
1) 192.168.1.10 - 110000 packets
2) 192.168.1.11 - 100000 packets
3) 192.168.1.12 - 90000 packets
4) 192.168.1.13 - 80000 packets
5) 192.168.1.14 - 70000 packets

Malformed packets: 10
```

## Additional Information

### Code Structure

- `pcap_stats.cpp`: Main source code file containing all the logic for packet analysis.

### Key Functions and Structures

- `struct packet_stats`: A structure to hold packet statistics, including total packets, total volume, max packet size, TCP and UDP packets, malformed packets, and IP frequency maps.
- `packet_handler()`: Callback function to process each packet.
- `output_analysis()`: Outputs the analysis results.

### Future Improvements

- Enhance error handling and logging.
- Expand detection of malformed packets and anomalies.

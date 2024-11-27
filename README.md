# Traceroute

Written in Python using raw sockets, ICMP request, and reply messages.

## traceroute.py

Traceroute is a network diagnostic tool used to track the pathway taken by a packet on an IP network from source to destination. It records the IP addresses of all the routers it passes through until it reaches its destination or is discarded.  
In order to keep it simple, this program does not follow the official spec in RFC 1739. 

## Demo

[![asciicast](https://asciinema.org/a/oBjkDptRGJcYiEp8sMAtmovxR.svg)](https://asciinema.org/a/oBjkDptRGJcYiEp8sMAtmovxR)

## Instructions

To run traceroute.py: `sudo python3 traceroute.py [options] host`

### Options

- `-c, --count COUNT`: Number of packets to send per hop (default is 3).
- `-m, --maxhops MAXHOPS`: Maximum number of hops (default is 64).
- `-t, --timeout TIMEOUT`: Timeout in milliseconds for each reply (default is 4000 ms).
- `-p, --packet_size PACKET_SIZE`: Packet size in bytes (default is 38 bytes).
- `-d, --debug`: Enable debug mode for detailed output.

## Features

**Raw Socket Communication**  
Utilizes raw sockets to send and receive ICMP packets, providing low-level network access.

**TTL Manipulation**  
Adjusts the Time To Live (TTL) field in the IP header to control how far the packet can travel in the network. By incrementing the TTL value starting from 1, the script discovers each router (hop) along the path to the destination.

**ICMP Packet Construction**  
Manually constructs ICMP Echo Request packets, including headers and payload.

**Packet Unpacking and Route Mapping**   
Receives ICMP Time Exceeded and Echo Reply messages, parses the headers, and maps the route by extracting the IP addresses of intermediate routers.

**Round-Trip Time Calculation**  
Measures the time taken for packets to reach the target and return, providing RTT statistics.


## Environment

```
$ python3 --version
Python 3.13.0

$ uname
Darwin
```
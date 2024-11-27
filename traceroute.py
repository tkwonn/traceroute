from socket import *
import struct
import os
import time
import sys
import select
import argparse
from packet_builder import PacketBuilder
from packet_parser import PacketParser

ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
MIN_SLEEP = 1000

class Traceroute:
    def __init__(self, target_host, count_of_packets, packet_size, max_hops, timeout, debug):
        self.__target_host = target_host
        self.__count_of_packets = count_of_packets
        self.__packet_size = packet_size
        self.__max_hops = max_hops
        self.__timeout = timeout
        self.__identifier = os.getpid() & 0xffff
        self.__sequence_number = 0
        self.__debug = debug
        self.__ttl = 1
        try:
            self.__target_ip = gethostbyname(target_host)
        except gaierror:
            print(f"traceroute: unknown host {target_host}")
            sys.exit(1)

    def start_traceroute(self):
        while self.__ttl <= self.__max_hops:
            delays = []
            ip_header = None
            success = False
            try:
                for _ in range(self.__count_of_packets):
                    rtt, ip_hdr, icmp_header = self.__send_echo_request()
                    if rtt is not None:
                        delays.append(rtt)
                        ip_header = ip_hdr
                        if icmp_header['type'] == ICMP_ECHO_REPLY:
                            success = True
                    else:
                        delays.append(None)
            except KeyboardInterrupt:
                break

            if all(delay is None for delay in delays):
                self.__print_timeout()
            else:
                self.__print_trace(delays, ip_header)

            if success:
                break

            self.__ttl += 1

    def __send_echo_request(self):
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as icmp_socket:
                icmp_socket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.__ttl))
                self.__sequence_number += 1
                if self.__ttl == 1 and self.__sequence_number == 1:
                    print(f"\ntraceroute to {self.__target_host} ({self.__target_ip}), {self.__max_hops} hops max, {self.__packet_size} byte packets")

                packet_builder = PacketBuilder(self.__identifier, self.__sequence_number, self.__packet_size)
                packet = packet_builder.build_packet()

                icmp_socket.sendto(packet, (self.__target_host, 1))
                rtt, ip_header, icmp_header = self.__receive_echo_reply(icmp_socket)

                return rtt, ip_header, icmp_header
        except PermissionError:
            print("Permission denied: You need to run this script with root privilege.")
            sys.exit(1)
        except Exception as err:
            print(f"Exception occurred: {err}")
            sys.exit(1)

    def __receive_echo_reply(self, icmp_socket):
        timeout = self.__timeout / 1000

        while True:
            input_ready, _, _ = select.select([icmp_socket], [], [], timeout)

            if not input_ready:
                return None, None, None

            packet_data, address = icmp_socket.recvfrom(2048)
            receive_time = time.time()

            parser = PacketParser(packet_data, self.__debug)

            icmp_header = parser.parse_icmp_header()
            ip_header = parser.parse_ip_header()
            
            send_timestamp = parser.parse_timestamp(icmp_header['type'])
            if send_timestamp is None:
                return None, None, None

            rtt = (receive_time - send_timestamp) * 1000.0

            return rtt, ip_header, icmp_header

    def __print_timeout(self):
        print(f"{self.__ttl:<3} ", end="")
        for _ in range(self.__count_of_packets):
            print("* ", end="")
        print()

    def __print_trace(self, delays, ip_header):
        if ip_header is None:
            print(f"{self.__ttl:<3} ", end="")
        else:
            ip = ip_header['Source_IP']
            try:
                sender_hostname = gethostbyaddr(ip)[0]
            except herror:
                sender_hostname = ip
            print(f"{self.__ttl:<3} {sender_hostname} ({ip}) ", end="")

        for delay in delays:
            if delay is not None:
                print(f"{delay:.3f} ms ", end="")
            else:
                print("* ", end="")
        print()

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('-c', '--count', required=False, nargs='?', default=3, type=int, metavar='Count of packets')
    parser.add_argument('-m', '--maxhops', required=False, nargs='?', default=64, type=int, metavar='Max hops')
    parser.add_argument('-t', '--timeout', required=False, nargs='?', default=4000, type=int, metavar='Timeout in ms')
    parser.add_argument('-p', '--packet_size', required=False, nargs='?', default=38, type=int,
                        metavar='Packet size in bytes')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    return parser

if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    t = Traceroute(args.host, args.count, args.packet_size, args.maxhops, args.timeout, args.debug)
    t.start_traceroute()

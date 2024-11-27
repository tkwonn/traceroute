
import struct
import socket

IP_HEADER_SIZE = 20
ICMP_HEADER_SIZE = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11

class PacketParser:
    def __init__(self, packet_data, debug):
        self.__packet_data = packet_data
        self.__debug = debug

    def parse_icmp_header(self):
        icmp_header = self.__packet_data[IP_HEADER_SIZE:IP_HEADER_SIZE + ICMP_HEADER_SIZE]
        icmp_keys = ['type', 'code', 'checksum', 'identifier', 'sequence_number']
        icmp_header_unpacked = struct.unpack("!BBHHH", icmp_header)

        if self.__debug:
            print("\nUnpacked ICMP Header: ", icmp_header_unpacked)
        
        icmp_header_dict = dict(zip(icmp_keys, icmp_header_unpacked))
        return icmp_header_dict

    def parse_ip_header(self):
        ip_header = self.__packet_data[:IP_HEADER_SIZE]
        ip_keys = [
            'VersionIHL', 'Type_of_Service', 'Total_Length', 'Identification',
            'Flags_FragOffset', 'TTL', 'Protocol', 'Header_Checksum',
            'Source_IP', 'Destination_IP'
        ]
        ip_header_unpacked = struct.unpack("!BBHHHBBHII", ip_header)

        if self.__debug:
            print("\nUnpacked IP Header: ", ip_header_unpacked)
        
        ip_header_dict = dict(zip(ip_keys, ip_header_unpacked))
        ip_header_dict['Source_IP'] = socket.inet_ntoa(struct.pack('!I', ip_header_dict['Source_IP']))
        ip_header_dict['Destination_IP'] = socket.inet_ntoa(struct.pack('!I', ip_header_dict['Destination_IP']))
        return ip_header_dict
    
    def parse_timestamp(self, icmp_type):
        if icmp_type == ICMP_ECHO_REPLY:
            data_offset = IP_HEADER_SIZE + ICMP_HEADER_SIZE
        elif icmp_type == ICMP_TIME_EXCEEDED:
            # When error message is returned, the original IP header and the first 8 bytes of the original datagram's data are included
            data_offset = (IP_HEADER_SIZE + ICMP_HEADER_SIZE) * 2
        else:
            return None
        
        timestamp_data = self.__packet_data[data_offset:data_offset + 8]
        if len(timestamp_data) < 8:
            return None
        timestamp = struct.unpack("!d", timestamp_data)[0]
        return timestamp

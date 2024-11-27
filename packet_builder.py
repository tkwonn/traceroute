import struct
import os
import sys
import time
import socket

class PacketBuilder:
    ICMP_ECHO = 8

    def __init__(self, identifier, sequence_number, packet_size, debug=False):
        self.__identifier = identifier
        self.__sequence_number = sequence_number
        self.__packet_size = packet_size
        self.__debug = debug

    def build_packet(self):
        header = self.__pack_header(checksum=0)
        data = self.__encode_data()
        checksum = self.__calculate_checksum(header + data)
        # Re-pack the header with the correct checksum
        header = self.__pack_header(checksum=checksum)

        packet = header + data
        return packet

    def __pack_header(self, checksum):
        # Pack (Serialize) the header with network byte order (big-endian)
        header = struct.pack(
            "!BBHHH",
            self.ICMP_ECHO,         # Type
            0,                      # Code
            checksum,               # Checksum
            self.__identifier,      # Identifier (PID)
            self.__sequence_number  # Sequence number
        )

        if self.__debug:
            # e.g., b'\x08\x00\x1c-\x30\x39\x00\x01'
            print("Packed Header: ", header)

        return header

    def __encode_data(self):
        # Storing send time information in the data field is often used as a techinque # to calculate the RTT since it can be extracted from the reply packet.
        timestamp = struct.pack("!d", time.time())
        payload_size = self.__packet_size - struct.calcsize("!d")
        payload = []
        for i in range(payload_size):
            payload.append((65 + i) & 0xff) # Keep values between 65 and 255
        
        data = timestamp + bytes(payload)
        return data

    def __calculate_checksum(self, packet):
        countTo = (len(packet) // 2) * 2
        count = 0
        sum = 0

        while count < countTo:
            if (sys.byteorder == "little"):
                loByte = packet[count]
                hiByte = packet[count + 1]
            else:
                loByte = packet[count + 1]
                hiByte = packet[count]
            sum = sum + (hiByte * 256 + loByte)
            count += 2

        if countTo < len(packet):
            sum += packet[count]

        sum = (sum >> 16) + (sum & 0xffff)  # Adding higher and lower 16 bits
        sum += (sum >> 16)
        answer = ~sum & 0xffff
        answer = socket.htons(answer)

        return answer
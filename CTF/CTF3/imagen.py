from scapy.all import *
import random
import struct
import socket
from socket import inet_aton

# Define the path to the image
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\chilean_hotdog.jpg"

# Read the image file as bytes
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Ethernet frame
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:fc:48:dd:ee:ff")

# IP packet
ip = IP(src="192.168.0.10", dst="192.168.0.1")

# TCP parameters
dport = 80
seq = random.randint(1, 4294967295)  # Random initial sequence number
ack = 0  # No acknowledgment in the initial SYN packet
max_segment_size = 1460  # Adjust this value as needed

# Calculate the TCP checksum for each segment
segments = [
    image_data[i : i + max_segment_size]
    for i in range(0, len(image_data), max_segment_size)
]

packets = []

for segment in segments:
    # TCP segment
    sport = random.randint(1024, 65535)
    tcp = TCP(sport=sport, dport=dport, flags="S", seq=seq, ack=ack, chksum=0)

    # Calculate the TCP checksum
    pseudo_header = struct.pack(
        "!4s4sBBH",
        inet_aton(ip.src),
        inet_aton(ip.dst),
        0,
        ip.proto,
        len(tcp) + len(segment),
    )
    tcp_len = len(tcp) + len(segment)
    checksum = 0

    # Sum pseudo-header
    for i in range(0, len(pseudo_header), 2):
        checksum += (pseudo_header[i] << 8) + pseudo_header[i + 1]

    # Sum TCP header
    tcp_header_bytes = bytes(tcp)
    for i in range(0, len(tcp_header_bytes), 2):
        checksum += (tcp_header_bytes[i] << 8) + tcp_header_bytes[i + 1]

    # Sum segment bytes (padded if necessary)
    for i in range(0, len(segment), 2):
        byte1 = segment[i]
        byte2 = segment[i + 1] if i + 1 < len(segment) else 0
        checksum += (byte1 << 8) + byte2

    # Add carry to the checksum
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Set the checksum in the TCP header
    tcp.chksum = socket.htons(~checksum & 0xFFFF)

    # Create the final packet with the image data segment
    packet = eth / ip / tcp / segment
    packets.append(packet)

# Save the packets to a PCAP file
output_pcap = "ctf3_image.pcap"
wrpcap(output_pcap, packets)

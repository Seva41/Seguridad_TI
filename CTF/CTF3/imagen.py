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
ip = IP(
    src="192.168.0.10",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",  # Set the Don't Fragment (DF) flag
    id=32711,
    len=0,  # Set the length to 0 for automatic calculation
    chksum=0,
)

# Crea el paquete TCP with a valid seq number
tcp = TCP(
    sport=12345,
    dport=80,
    flags="S",
    seq=1000,  # Set a valid 32-bit sequence number
    options=[("Timestamp", (0, 0))],
    chksum=0,
)

# Define el paquete completo
packet = eth / ip / tcp / Raw(load=image_data)

# Calculate the TCP checksum
packet[TCP].chksum = 0  # Clear the existing checksum field
packet = packet.__class__(bytes(packet))
packet[TCP].chksum = None  # Recalculate the checksum

# Define el path del archivo .pcap
output_pcap = "imagen.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)

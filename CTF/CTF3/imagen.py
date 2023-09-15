from scapy.all import *

# Read the image file and convert it to binary data
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\chilean_hotdog.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:fc:48:dd:ee:ff")
ip = IP(
    src="192.168.0.10",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",
    id=32711,
    len=1200,
    chksum=0,
)

# Create a TCP segment
tcp = TCP(
    sport=12345,
    dport=80,
    flags="S",
    seq=1000,
    options=[("Timestamp", (0, 0))],
    chksum=0,
)

packet = eth / ip / tcp / Raw(load=image_data)


del packet[IP].chksum
del packet[TCP].chksum

# Insert your image data into the payload


packet = packet.__class__(bytes(packet))

# Define the output .pcap file name
output_pcap = "imagen.pcap"

# Write the packet to the .pcap file
wrpcap(output_pcap, packet)

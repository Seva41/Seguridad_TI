from scapy.all import *

# Lee la imagen a enviar en bytes
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\earthquake.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:f1:36:dd:ee:ff")
ip = IP(
    src="192.168.0.15",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",  # Set the Don't Fragment (DF) flag
    id=32713,
    len=0,  # Set the length to 0 for automatic calculation
    chksum=0,
)

# Crea el paquete TCP with a valid seq number
tcp = TCP(
    sport=12348,
    dport=80,
    flags="S",
    seq=5000,  # Set a valid 32-bit sequence number
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
output_pcap = "basura1.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)


# Lee la imagen a enviar en bytes
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\nocats.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:64:ba:cc:ee:ff")
ip = IP(
    src="192.168.0.18",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",  # Set the Don't Fragment (DF) flag
    id=32714,
    len=0,  # Set the length to 0 for automatic calculation
    chksum=0,
)

# Crea el paquete TCP with a valid seq number
tcp = TCP(
    sport=12347,
    dport=80,
    flags="S",
    seq=10000,  # Set a valid 32-bit sequence number
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
output_pcap = "basura2.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)


# Lee la imagen a enviar en bytes
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\sadoless.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="f8:a9:d0:dd:ab:ff")
ip = IP(
    src="192.168.0.22",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",  # Set the Don't Fragment (DF) flag
    id=32715,
    len=0,  # Set the length to 0 for automatic calculation
    chksum=0,
)

# Crea el paquete TCP with a valid seq number
tcp = TCP(
    sport=12346,
    dport=80,
    flags="S",
    seq=15000,  # Set a valid 32-bit sequence number
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
output_pcap = "basura3.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)

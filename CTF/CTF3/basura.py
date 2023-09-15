from scapy.all import *

# Lee la imagen a enviar en bytes
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\earthquake.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:f1:36:dd:ee:ff")
ip = IP(
    src="192.168.0.25",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",
    id=32711,
    len=1200,
    chksum=0,
)

# Crea el paquete TCP
tcp = TCP(
    sport=12346,
    dport=80,
    flags="S",
    seq=1800,
    options=[("Timestamp", (0, 0))],
    chksum=0,
)

# Define el paquete completo
packet = eth / ip / tcp / Raw(load=image_data)

# Borra los checksums para que Scapy los calcule automáticamente
del packet[IP].chksum
del packet[TCP].chksum

# Recalcula los checksums
packet = packet.__class__(bytes(packet))

# Define el path del archivo .pcap
output_pcap = "basura.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)


# Lee la imagen a enviar en bytes
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\nocats.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(dst="fc:f8:ae:33:44:55", src="fc:64:ba:cc:ee:ff")
ip = IP(
    src="192.168.0.41",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",
    id=32731,
    len=1200,
    chksum=0,
)

# Crea el paquete TCP
tcp = TCP(
    sport=12326,
    dport=80,
    flags="S",
    seq=2700,
    options=[("Timestamp", (0, 0))],
    chksum=0,
)

# Define el paquete completo
packet = eth / ip / tcp / Raw(load=image_data)

# Borra los checksums para que Scapy los calcule automáticamente
del packet[IP].chksum
del packet[TCP].chksum

# Recalcula los checksums
packet = packet.__class__(bytes(packet))

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
    src="192.168.0.41",
    dst="192.168.0.1",
    ttl=64,
    flags="DF",
    id=32731,
    len=1200,
    chksum=0,
)

# Crea el paquete TCP
tcp = TCP(
    sport=12326,
    dport=80,
    flags="S",
    seq=3680,
    options=[("Timestamp", (0, 0))],
    chksum=0,
)

# Define el paquete completo
packet = eth / ip / tcp / Raw(load=image_data)

# Borra los checksums para que Scapy los calcule automáticamente
del packet[IP].chksum
del packet[TCP].chksum

# Recalcula los checksums
packet = packet.__class__(bytes(packet))

# Define el path del archivo .pcap
output_pcap = "basura3.pcap"

# Escribe el paquete en el archivo .pcap
wrpcap(output_pcap, packet)

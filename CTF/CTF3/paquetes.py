from scapy.all import *

# Define el path de la imagen a enviar
image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\chilean_hotdog.jpg"
with open(image_path, "rb") as image_file:
    image_data = image_file.read()

# Define la llave secreta
secret_key = 0x5A  # Cualquier número entre 0 y 255 (hexadecimal)

# Encripta la imagen
encrypted_image_data = bytes([byte ^ secret_key for byte in image_data])

# Define la lista de paquetes
packets = []

# Define los paquetes a enviar (ethernet, ip, tcp, datos)
eth = Ether(
    dst="fc:f8:ae:33:44:55", src="fc:fc:48:dd:ee:ff"
)  # MAC origen Apple, MAC destino Intel
ip = IP(src="192.168.0.10", dst="192.168.0.1")
tcp = TCP(sport=12345, dport=80, flags="S", seq=1000)

# Define el paquete con los datos de la imagen encriptada
packet = eth / ip / tcp / encrypted_image_data
packets.append(packet)

# Define el path del archivo pcap de salida
output_pcap = "ctf3_encrypted.pcap"

# Guarda los paquetes en el archivo pcap
wrpcap(output_pcap, packets)

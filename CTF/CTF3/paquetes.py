from scapy.all import *
import random
import struct
import socket


def imagen(packets, sec):
    # Define el path de la imagen a enviar
    image_path = r"C:\Users\sebad\OneDrive - Universidad Adolfo Ibanez\Ayudantía Pregrado\Seguridad TI 2023-2\CTF\CTF3\chilean_hotdog.jpg"
    with open(image_path, "rb") as image_file:
        image_data = image_file.read()

    # Define la llave secreta
    secret_key = 0x5A  # Cualquier número entre 0 y 255 (hexadecimal)

    # Encripta la imagen con XOR
    encrypted_image_data = bytes([byte ^ secret_key for byte in image_data])

    # Define los paquetes a enviar (ethernet, ip, tcp, datos)
    eth = Ether(
        dst="fc:f8:ae:33:44:55", src="fc:fc:48:dd:ee:ff"
    )  # MAC origen Apple, MAC destino Intel
    ip = IP(src="192.168.0.10", dst="192.168.0.1")

    # Define unique source and destination port numbers for TCP
    sport = random.randint(1024, 65535)
    dport = 80
    seq = sec + len(encrypted_image_data)
    tcp = TCP(sport=sport, dport=dport, flags="S", seq=sec + 1)

    # Manually calculate and set TCP checksum
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(ip.src),
        socket.inet_aton(ip.dst),
        0,
        ip.proto,
        len(tcp),
    )
    checksum = sum(
        struct.unpack("!H", pseudo_header[i : i + 2])[0]
        for i in range(0, len(pseudo_header), 2)
    )
    checksum += sum(
        struct.unpack("!H", tcp)[0]
        for tcp in struct.pack(
            "!HHH",
            int(ip.src.split(".")[0]),
            int(ip.src.split(".")[1]),
            int(ip.src.split(".")[2]),
        )
    )
    checksum += sum(
        struct.unpack("!H", tcp)[0]
        for tcp in struct.pack(
            "!HHH",
            int(ip.dst.split(".")[0]),
            int(ip.dst.split(".")[1]),
            int(ip.dst.split(".")[2]),
        )
    )
    checksum += socket.IPPROTO_TCP + len(tcp)
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    tcp.chksum = socket.htons((checksum & 0xFFFF) + (checksum >> 16))

    # Define el paquete con los datos de la imagen encriptada
    packet = eth / ip / tcp / encrypted_image_data
    packets.append(packet)

    return packets, seq


def fake(packets, sec):
    # Define the list of predefined garbage messages
    garbage_messages = [
        b"This is a fake message 1",
        b"Another fake message here",
        b"n00b",
        b"Random garbage message",
        b"gg ez",
        b"viva mexico y los tacos",
    ]
    random_message = random.choice(garbage_messages)  # Move random_message here

    # Define los paquetes a enviar (ethernet, ip, tcp, datos)
    eth = Ether(
        dst="fc:f8:ae:33:44:55", src="fc:f1:36:aa:bc:cd"
    )  # MAC origen Samsung, MAC destino Intel
    ip = IP(src="192.168.0.15", dst="192.168.0.1")

    # Define unique source and destination port numbers for TCP
    sport = random.randint(1024, 65535)
    dport = 80

    tcp = TCP(sport=sport, dport=dport, flags="S", seq=sec + 1)
    sec = sec + 1
    payload = random_message

    packet = eth / ip / tcp / payload
    packets.append(packet)

    return packets, sec


# Define la lista de paquetes
packets = []
seq = 1000

for i in range(20):
    if i == 7:
        packets, seq = imagen(packets, seq)
    else:
        packets, seq = fake(packets, seq)
    i += 1

# Define el path del archivo pcap de salida
output_pcap = "ctf3_encrypted.pcap"

# Guarda los paquetes en el archivo pcap
wrpcap(output_pcap, packets)

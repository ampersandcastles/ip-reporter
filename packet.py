import socket
from struct import pack

def send_arp_packet():
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source MAC address
    dst_ip = "192.168.1.1"  # Destination IP address

    # Craft the ARP request packet
    arp_packet = b'\xff\xff\xff\xff\xff\xff'  # Destination MAC address (broadcast)
    arp_packet += src_mac
    arp_packet += b'\x08\x06'  # Ethernet type: ARP
    arp_packet += b'\x00\x01'  # ARP hardware type: Ethernet
    arp_packet += b'\x08\x00'  # ARP protocol type: IPv4
    arp_packet += b'\x06'  # Hardware address length
    arp_packet += b'\x04'  # Protocol address length
    arp_packet += b'\x00\x01'  # Operation code: ARP request
    arp_packet += src_mac  # Sender hardware address
    arp_packet += socket.inet_aton(src_ip)  # Sender protocol address
    arp_packet += b'\x00\x00\x00\x00\x00\x00'  # Target hardware address (unknown)
    arp_packet += socket.inet_aton(dst_ip)  # Target protocol address

    # Create a raw socket and send the ARP packet
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
    raw_socket.bind(("wlp61s0", 0))
    raw_socket.send(arp_packet)
    raw_socket.close()

if __name__ == "__main__":
    send_arp_packet()

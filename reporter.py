from scapy.all import IP, UDP, Ether, sniff

# Define the destination IP address and UDP ports to filter
destination_ip = '255.255.255.255'  # Destination IP address
source_port = 14236  # Source port
destination_port = 14235  # Destination port

def extract_packet_info(packet):
    # Check if the packet is an IP packet with UDP layer
    if IP in packet and UDP in packet:
        # Extract the source IP address, source port, and destination port
        source_ip = packet[IP].src
        udp_source_port = packet[UDP].sport
        udp_destination_port = packet[UDP].dport
        
        # Check if the packet matches the specified destination IP address and UDP ports
        if (packet[IP].dst == destination_ip and
            udp_source_port == source_port and
            udp_destination_port == destination_port):
            # Extract and print the MAC address from the Ethernet layer
            source_mac = packet[Ether].src
            print(f"Miner IP: {source_ip}")
            print(f"Source MAC Address: {source_mac}")
            #print(f"UDP Source Port: {udp_source_port}")
            #print(f"UDP Destination Port: {udp_destination_port}")
            print("-" * 40)

def listen_for_packets():
    # Sniff network traffic and invoke the callback function for each packet
    sniff(prn=extract_packet_info, filter="udp and ip", store=0)

if __name__ == "__main__":
    # Start listening for packets
    print("Listening...")
    listen_for_packets()

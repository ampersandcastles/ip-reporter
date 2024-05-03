from scapy.all import IP, UDP, sniff

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
            print("Miner IP:", source_ip)
            #print("UDP Source Port:", udp_source_port)
            #print("UDP Destination Port:", udp_destination_port)

def listen_for_packets():
    # Sniff network traffic and invoke the callback function for each packet
    sniff(prn=extract_packet_info, filter="udp and ip", store=0)

if __name__ == "__main__":
    # Start listening for packets
    listen_for_packets()

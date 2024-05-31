import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import IP, UDP, Ether, sniff
import webbrowser

# Define the destination IP address and UDP ports to filter
destination_ip = '255.255.255.255'  # Destination IP address
source_port = 14236  # Source port
destination_port = 14235  # Destination port

# Username and password for the miners
# Adjust accordingly for appropriate credentials
username = "root"
password = "root"

# Function to extract packet information and display it in the tree view
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
            # Extract the MAC address from the Ethernet layer
            source_mac = packet[Ether].src
            # Display the information in the tree view
            tree.insert("", tk.END, values=(source_ip, source_mac))

# Function to start listening for packets
def listen_for_packets():
    sniff(prn=extract_packet_info, filter="udp and ip", store=0)

# Function to start/stop the packet listening
def toggle_listening():
    global listening
    if not listening:
        # Start listening for packets in a separate thread
        import threading
        threading.Thread(target=listen_for_packets, daemon=True).start()
        start_button.config(text="Stop")
        status_label.config(text="Listening...")
        listening = True
    else:
        # Stop listening for packets (terminate the program)
        start_button.config(text="Start")
        status_label.config(text="Stopped")
        listening = False

# Function to export the data to a file
def export_data():
    # Get the file path from the user
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                             filetypes=[("Text files", "*.txt"), 
                                                        ("All files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            for row_id in tree.get_children():
                row = tree.item(row_id)['values']
                file.write(f"IP Address: {row[0]}, MAC Address: {row[1]}\n")
        status_label.config(text=f"Data exported to {file_path}")

# Function to open the IP address in the default web browser with credentials
def open_in_browser(event):
    item = tree.selection()[0]
    ip_address = tree.item(item, "values")[0]
    url = f"http://{username}:{password}@{ip_address}"
    webbrowser.open(url)

# Create the main window
root = tk.Tk()
root.title("IP Reporter")

# Create a frame for the tree view
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# Create a tree view with columns for IP and MAC
columns = ("IP Address", "MAC Address")
tree = ttk.Treeview(frame, columns=columns, show="headings")
tree.heading("IP Address", text="IP Address")
tree.heading("MAC Address", text="MAC Address")
tree.pack(fill=tk.BOTH, expand=True)

# Bind double click to open in browser
tree.bind("<Double-1>", open_in_browser)

# Create a start button
start_button = tk.Button(root, text="Start", command=toggle_listening)
start_button.pack(pady=5)

# Create an export button
export_button = tk.Button(root, text="Export", command=export_data)
export_button.pack(pady=5)

# Create a status label
status_label = tk.Label(root, text="Stopped")
status_label.pack(pady=5)

# Start the Tkinter event loop
listening = False
root.mainloop()

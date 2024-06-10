from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, QPushButton, QFileDialog, QLabel
from PyQt5.QtCore import Qt
from scapy.all import IP, UDP, Ether, sniff
import webbrowser
import sys
import threading
import os

# Define the destination IP address and UDP ports to filter
destination_ip = '255.255.255.255'  # Destination IP address
source_port = 14236  # Source port
destination_port = 14235  # Destination port

# Username and password for the miners
username = "root"
password = "root"

class IPReporter(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("IP Reporter")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["IP Address", "MAC Address"])
        self.tree.setColumnWidth(1, 400)
        self.layout.addWidget(self.tree)
        
        self.tree.itemDoubleClicked.connect(self.open_in_browser)
        
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.toggle_listening)
        self.layout.addWidget(self.start_button)
        
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_data)
        self.layout.addWidget(self.export_button)
        
        self.status_label = QLabel("Stopped")
        self.layout.addWidget(self.status_label)
        
        self.listening = False

        # Set to keep track of unique IP addresses
        self.unique_ips = set()

    def extract_packet_info(self, packet):
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

                # Check if the IP address is already in the set
                if source_ip not in self.unique_ips:
                    # Add the IP address to the set
                    self.unique_ips.add(source_ip)
                    # Display the information in the tree view
                    self.tree.addTopLevelItem(QTreeWidgetItem([source_ip, source_mac]))

    def listen_for_packets(self):
        sniff(prn=self.extract_packet_info, filter="udp and ip", store=0)

    def toggle_listening(self):
        if not self.listening:
            # Start listening for packets in a separate thread
            threading.Thread(target=self.listen_for_packets, daemon=True).start()
            self.start_button.setText("Stop")
            self.status_label.setText("Listening...")
            self.listening = True
        else:
            # Stop listening for packets (terminate the program)
            self.start_button.setText("Start")
            self.status_label.setText("Stopped")
            self.listening = False

    def export_data(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, "w") as file:
                for i in range(self.tree.topLevelItemCount()):
                    item = self.tree.topLevelItem(i)
                    ip_address = item.text(0)
                    mac_address = item.text(1)
                    file.write(f"IP Address: {ip_address}, MAC Address: {mac_address}\n")
            self.status_label.setText(f"Data exported to {file_path}")

    def open_in_browser(self, item):
        ip_address = item.text(0)
        url = f"http://{username}:{password}@{ip_address}"
        webbrowser.open(url)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IPReporter()
    window.show()
    sys.exit(app.exec_())

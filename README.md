# PRODIGY_CS_05
This is my **5th task** of **Prodigy summer internship** based on **Network packet Analyser**.

In this, I make a scipt that captures and  analyzes network packets.Also display relevant information such as source and destination IP addresses, protocols,and payloads data.

**Summary**
1.**Importing Scapy**: Import Scapy functions and classes.
**from scapy.all import***: This imports all the necessary functions and classes from the Scapy library, including packet capturing and manipulation functions.

2.**Packet Handling**: Define how to process and display information from captured packets.

**def packet_handler(packet):**: Defines a function to handle each packet captured by Scapy.

**if IP in packet:**: Checks if the packet contains an IP layer. This ensures that only IP packets are processed.

**src_ip = packet[IP].src and dst_ip = packet[IP].dst**: Extracts the source and destination IP addresses from the packet.
**protocol = packet[IP].proto**: Retrieves the protocol number used in the IP packet (e.g., TCP, UDP, ICMP).
**Protocol Check**: Converts the protocol number to a human-readable name:
**6 is TCP
17 is UDP
1 is ICMP**
Other values are labeled as "**Unknown**".
**payload = str(packet[Raw].load) if Raw in packet else "No Payload"**: Checks if the packet contains raw payload data and prints it. If there is no raw data, it prints "No Payload".

3.**Start Sniffer**: Capture packets on a specified network interface and process each packet using the defined handler.
**def start_sniffer(interface=None):**: Defines a function to start the packet sniffer.
**print(f"Starting packet capture on {interface or 'all interfaces'}...")**: Prints a message indicating which network interface is being used for capturing packets. If no interface is specified, it will default to all available interfaces.
**sniff(iface=interface, prn=packet_handler, store=0)**: Calls Scapy’s sniff function to start capturing packets.
**iface=interface**: Specifies the network interface to listen on (e.g., "eth0", "wlan0"). If None, it listens on all interfaces.
**prn=packet_handle**r: Specifies the callback function (packet_handler) to process each captured packet.
**store=0**: Prevents storing packets in memory, which can save resources but might limit some functionalities.

4.**Main Function**: Execute the sniffer with default settings.
**def main():**: Defines the main function.
**interface = None**: Sets the network interface to None, meaning packets will be captured from all interfaces.
**start_sniffer(interface)**: Calls the start_sniffer function to begin capturing packets on the specified interface.

5.**Script Execution**: **if __name__ == "__main__":**: Ensures that the main() function is executed only when the script is run directly, not when it is imported as a module in another script.


from scapy.all import *
def packet_handler(packet):
    if IP in packet:            # type: ignore
        src_ip = packet[IP].src # type: ignore
        dst_ip = packet[IP].dst # type: ignore
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        
        # Display the protocol
        protocol = packet[IP].proto # type: ignore
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Unknown"
        print(f"Protocol: {protocol_name}")
        payload = str(packet[Raw].load) if Raw in packet else "No Payload"
        print(f"Payload: {payload}\n")
def start_sniffer(interface=None):
    print(f"Starting packet capture on {interface or 'all interfaces'}...")
    sniff(iface=interface, prn=packet_handler, store=0)
def main():
    interface = None
    start_sniffer(interface)

if __name__ == "__main__":
    main()


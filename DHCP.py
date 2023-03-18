from scapy.all import*
import ipaddress
import time
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

broadcast = "255.255.255.255"
serverIP = "192.168.1.190"
IPs = []


def listen():
    sniff(filter="udp and (port 67 or port 68)", prn=catch_discover, count=1)


# Check if DHCP packet is a discover
def catch_discover(packet):
    time.sleep(1)
    # 1 is discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print("[+] DHCP discover packet captured!")
        create_offer(packet)


# creating a DHCP offer packet
def create_offer(packet):
    optional_ip = IPs.pop(0)  # IP address to offer to the client
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src=serverIP, dst=broadcast)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=optional_ip, siaddr=serverIP, chaddr=packet[Ether].src, xid=packet[BOOTP].xid)
    dhcp = DHCP(options=[("message-type", "offer"), ("server_id", serverIP), "end"])
    offer_packet = ether / ip / udp / bootp / dhcp
    sendp(offer_packet, iface="wlp0s20f3")
    print("[+] DHCP offer packet sent!")
    sniff(filter="udp and (port 67 or port 68)", prn=catch_request, count=1)


# Check if DHCP packet is a request
def catch_request(packet):
    time.sleep(1)
    # 3 is request
    if DHCP in packet and packet[DHCP].options[0][1] == 3:
        print("[+] DHCP request packet captured!")
        create_ack(packet)


# creating a DHCP ack packet
def create_ack(packet):
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src=serverIP, dst=broadcast)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr=serverIP, chaddr=packet[Ether].src, xid=packet[BOOTP].xid)
    dhcp = DHCP(options=[("message-type", "ack"), ("name_server", "192.168.1.180"), "end"])
    ack_packet = ether / ip / udp / bootp / dhcp
    sendp(ack_packet, iface="wlp0s20f3")
    print("[+] DHCP ack packet sent!")


# creating a list of IPs in the subnet range
def create_ip_list(network):
    global IPs
    network_range = ipaddress.ip_network(network)
    # Iterate through the IP addresses in the network and add them to the global list
    for ip_address in network_range:
        IPs.append(str(ip_address))


if __name__ == "__main__":
    network = "192.168.1.0/24"
    create_ip_list(network)
    listen()

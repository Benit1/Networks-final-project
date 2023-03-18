from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

serverIP = "192.168.1.180"
AppID = "127.0.0.200"


def listen():
    sniff(filter=f"udp port 53 and ip dst {serverIP}", prn=catch_request, count=1)


# Check if DNS packet is arequest offer
def catch_request(packet):
    time.sleep(1)
    # opcode 0: a standard query ancount 0: not contains any response
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
        if IP in packet:
            print("[+] DNS request packet captured!")
            create_response(packet)


# creating a DNS response packet
def create_response(packet):
    time.sleep(1)
    domain = packet[DNSQR].qname.decode('utf-8')
    ip = IP(src=serverIP, dst=packet[IP].src)
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
    dns = DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=domain, type='A', rdata=AppID))
    response_packet = ip / udp / dns
    send(response_packet)
    print("[+] DNS response packet sent!")
    time.sleep(10)


if __name__ == '__main__':
    listen()

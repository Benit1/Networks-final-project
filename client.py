from scapy.all import *
from scapy.all import get_if_hwaddr
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import time
import requests

BRApp_ip = ""
client_ip = ""
dns_ip = ""
client_mac = get_if_hwaddr("wlp0s20f3")

broadcast = "255.255.255.255"


# creating a DHCP discover packet
def create_discover():
    time.sleep(1)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src='0.0.0.0', dst=broadcast)
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=client_mac)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    dhcp_discover_packet = ether / ip / udp / bootp / dhcp
    sendp(dhcp_discover_packet, iface="wlp0s20f3")
    print("[+] DHCP discover packet sent!")
    listen()


# Check if DHCP packet is an offer
def catch_offer(packet):
    time.sleep(1)
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        print("[+] DHCP offer packet captured!")
        time.sleep(0.5)
        ip_offer = packet[BOOTP].yiaddr
        print("Offered IP address: ", ip_offer)
        create_request(ip_offer)


# Start sniffing for DHCP offer packets
def listen():
    sniff(filter='udp and (port 67 or port 68)', prn=catch_offer, count=1)


# creating a DHCP request packet
def create_request(chosen_ip):
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst=broadcast)
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=client_mac, yiaddr=chosen_ip)
    dhcp = DHCP(options=[("message-type", "request"), "end"])
    dhcp_request_packet = eth / ip / udp / bootp / dhcp
    sendp(dhcp_request_packet, iface="wlp0s20f3")
    print("[+] DHCP request packet sent!")
    # Start sniffing for DHCP ack packets
    sniff(filter='udp and (port 67 or port 68)', prn=catch_ack, count=2)


# Check if DHCP packet is an ack
def catch_ack(packet):
    time.sleep(1)
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        global client_ip
        client_ip = packet[BOOTP].yiaddr
        for option in packet[DHCP].options:
            if option[0] == "name_server":
                # Extract the DNS IP address
                global dns_ip
                dns_ip = option[1]
                print("[+] DHCP ack packet captured!")
                create_dns_request()


# creating a DNS request packet
def create_dns_request():
    ip = IP(src=client_ip, dst=dns_ip)
    udp = UDP(sport=20235, dport=53)
    dns = DNS(id=1, rd=1, qd=DNSQR(qname="BRApp.com"))
    dns_request_packet = ip / udp / dns
    send(dns_request_packet)
    print("[+] DNS request packet sent!")
    # Start sniffing for DND response packets
    sniff(filter=f"udp port 53 and ip src {dns_ip}", prn=catch_dns_response, count=1)


# Check if DNS packet is a response
def catch_dns_response(packet):
    time.sleep(1)
    if DNS in packet and packet[DNS].qr == 1:
        print("[+] DNS response packet captured!")
        global BRApp_ip
        BRApp_ip = packet[DNSRR].rdata
        print("IP address of the App: ", BRApp_ip)
        http_server()


# reaching to server to get a file
def http_server():
    print("Which PDF file would you like to download?")
    time.sleep(1)
    while True:
        file_type = input("For wireshark enter 1\nFor proxy enter 2\nFor TCP enter 3\nFor Ping enter 4\nFor Sniffer enter 5\nFor Spoofing enter 6: ")
        match file_type:
            case "1":
                file_name = "wireshark"
                break
            case "2":
                file_name = "ProxyServer"
                break
            case "3":
                file_name = "TCP"
                break
            case "4":
                file_name = "Ping"
                break
            case "5":
                file_name = "Sniffer"
                break
            case "6":
                file_name = "Spoofer"
                break
            case _:
                print("[-] Invalid input, please enter a number between 1 and 6.")
    time.sleep(0.5)
    print("The file you chose to download is: " + file_name)
    url = f"http://127.0.0.200:80/{file_name}.pdf"
    response = requests.get(url)
    if response.status_code == 200:
        with open("downloaded_file.pdf", "wb") as file:
            file.write(response.content)
            print(f"[+] The required file '{file_name}' downloaded successfully as downloaded_file.pdf!")
    else:
        print("Error downloading file,\nhttp response:HTTP/1.1 404 Not Found\r\n\r\n")
        return
    return


if __name__ == '__main__':
    create_discover()


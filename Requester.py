from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff


def send_discover(src_mac):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
          UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=src_mac) / DHCP(options=[('message-type', 'discover'), 'end'])
    sendp(pkt, iface="Ethernet")


def receive_offer():
    return sniff(iface="Ethernet", filter="port 68 and port 67",
                 stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2)


def send_request(src_mac, request_ip, server_ip):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
          UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=src_mac) / \
          DHCP(options=[('message-type', 'request'), ("client_id", src_mac), ("requested_addr", request_ip),
                        ("server_id", server_ip), 'end'])
    sendp(pkt, iface="Ethernet")


def receive_acknowledge():
    return sniff(iface="Ethernet", filter="port 68 and port 67",
                 stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2)

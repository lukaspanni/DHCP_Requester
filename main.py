import random

import Requester


def random_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255))


if __name__ == "__main__":
    mac = random_mac()
    print("START")
    print("SEND: Discover")
    Requester.send_discover(mac)
    print("RECEIVE: Offer")
    pkts = Requester.receive_offer()
    server_mac = pkts[0]["Ether"].src
    bootp_reply = pkts[0]["BOOTP"]
    server_ip = bootp_reply.siaddr
    offered_ip = bootp_reply.yiaddr
    print("OFFER:", offered_ip)
    print("SEND: Request for", offered_ip)
    Requester.send_request(mac, offered_ip, server_ip)
    print("RECEIVE: Acknowledge")
    pkts2 = Requester.receive_acknowledge()
    print("ACKNOWLEDGE:", offered_ip)
    print("SEND: Test IP Packet")
    Requester.send_test_ip(mac, offered_ip, server_mac, server_ip)

import Requester

if __name__ == "__main__":
    print("START")
    print("SEND: Discover")
    Requester.send_discover("aa:bb:cc:dd:ef:ff")
    print("RECEIVE: Offer")
    pkts = Requester.receive_offer()
    pkts[0].show()
    bootp_reply = pkts[0]["BOOTP"]
    server_ip = bootp_reply.siaddr
    offered_ip = bootp_reply.yiaddr
    print("OFFER:", offered_ip)
    print("SEND: Request for", offered_ip)
    Requester.send_request("aa:bb:cc:dd:ee:ff", offered_ip, server_ip)
    print("RECEIVE: Acknowledge")
    pkts2 = Requester.receive_acknowledge()
    pkts2[0].show()
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
plist = []

def func(pkt):
    # called on each packet
    if HTTP in pkt:
        if HTTPResponse in pkt:
            # status codes are only in responses
            status = pkt[HTTPResponse].Status_Code
            if int(status) in [200, 429]: # check code
                plist.append(pkt)
                print(status)

sniff(offline="./tcp3.pcap", prn=func, store=False, session=TCPSession)


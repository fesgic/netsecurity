import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *
a = "wlan0"

def packet_capture():
    pkts = sniff(filter="tcp", iface=a, prn=lambda x: x.summary())
    # a = pkts.summary()
    print(pkts)

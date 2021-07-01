import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *



def packet_capture():

    pkts = sniff(iface="wlan0", prn=lambda x: x.summary())
    wrpcap(file, pkts)
    print(pkts)

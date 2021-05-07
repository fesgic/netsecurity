import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *



def packet_capture():
    pkts = sniff(filter="tcp", iface="wlan0", prn=lambda x: x.summary())
    # a = pkts.summary()
    wrpcap("tcp2.pcap", pkts)
    print(pkts)

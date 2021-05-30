import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *



def packet_capture():

    pkts = sniff(prn=lambda x: x.summary())
    # a = pkts.summary()
    wrpcap("vm.pcap", pkts)
    print(pkts)

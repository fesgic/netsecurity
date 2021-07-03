import logging
import os

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *



def packet_capture():

    pkts = sniff(iface=interface, prn=lambda x: x.summary())
    wrpcap(file, pkts)
    print(pkts)
def permissions():
    os.system(f"chmod 777 {file}")
    

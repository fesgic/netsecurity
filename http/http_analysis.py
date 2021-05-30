import pyshark
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap

plist = []

file = str(input("Enter name of file you want to analyze: "))
packets = rdpcap(file)
print("Capture has a total of ", len(packets), "packets")


def func(pkt):
    # called on each packet
    if HTTP in pkt:
        if HTTPResponse in pkt:
            # status codes are only in responses
            status = pkt[HTTPResponse].Status_Code
            if int(status) in [200, 429]:  # check code
                plist.append(pkt)
                print(status)

#def pyshark_retran_packet(file):
#    capture = pyshark.FileCapture(file, display_filter='tcp.analysis.retransmission')
#    counter = 0
#    for packet in capture:
#        counter = counter + 1
#    return counter
#print("Total number of retransmitted frames found = ",pyshark_retran_packet(file) )

def pyshark_retran_packet(file):
    capture = pyshark.FileCapture(file, display_filter='tcp.analysis.retransmission')
    counter = 0
    final=""
    for packet in capture:
        counter = counter + 1
        final=("Total number of retransmitted frames found = " + str(counter))
    return final

print(pyshark_retran_packet(file))

sniff(offline="./tcp3.pcap", prn=func, store=False, session=TCPSession)

#pyshark_retran_packet(file)



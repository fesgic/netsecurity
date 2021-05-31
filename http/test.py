import pyshark
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap
from http import HTTPStatus

plist = []
sorted_plist = []

# file = str(input("Enter name of file you want to analyze: "))
# packets = rdpcap(file)
# print("Capture has a total of ", len(packets), "packets")



def status_code_type(status_code):
    if 100 <= status_code <= 199:
        code = "Informational response"
        return code
    elif 200 <= status_code <= 299:
        code = "Successful responses"
        return code
    elif 300 <= status_code <= 399:
        code = "Server Redirects"
        return code
    elif 400 <= status_code <= 499:
        code = "Client Erros"
        return code
    elif 500 <= status_code <= 599:
        code = "Server Errors"
        return code
    else:
        return None


def func(pkt):
    # called on each packet
    for code in range(100, 600):
        status_code = [code]
        if HTTP in pkt and HTTPResponse in pkt:
            if HTTPResponse in pkt:
                # status codes are only in responses
                status = pkt[HTTPResponse].Status_Code             
                if int(status) in status_code:  # check code
                    for i in status_code:
                        print(HTTPStatus(i))
                        #print("src_mac: ",pkt.src,"dst_mac :",pkt.dst,"src_ip: ",pkt[IP].src,"dst_ip :",pkt[IP].dst)
                        plist.append(pkt)
                        print("\n")

print(plist)
sniff(offline="tcp3.pcap", prn=func, store=False, session=TCPSession)
#print(plist)
#print(type(plist[0]))
#for list in plist:
#plist.summary()

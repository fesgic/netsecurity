import pyshark
import sys
arguments=sys.argv
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap
#from http import HTTPStatus

plist = []

filename = arguments[1];
packets = rdpcap(filename)
print("Capture has a total of ", len(packets), "packets")

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


#def pyshark_retran_packet(file):
#    capture = pyshark.FileCapture(file, display_filter='tcp.analysis.retransmission')
#    counter = 0
#    for packet in capture:
#        counter = counter + 1
#    return counter
#print("Total number of retransmitted frames found = ",pyshark_retran_packet(file) )

def pyshark_retran_packet(filename):
    capture = pyshark.FileCapture(filename, display_filter='tcp.analysis.retransmission')
    counter = 0
    final=""
    for packet in capture:
        counter = counter + 1
        final=("Total number of retransmitted frames found = " + str(counter))
    return final

print(pyshark_retran_packet(filename))
#pyshark_retran_packet(filename)



def func(pkt):
    # called on each packet
    code = []
    stop=0
    for num in range(100, 600):
        code.append(num)
        
    if HTTP in pkt and HTTPResponse in pkt:
        if HTTPResponse in pkt:
            # status codes are only in responses
            status = pkt[HTTPResponse].Status_Code
            
            for status_code in code:
                if int(status_code) == int(status):
                    if (stop == 0):  # check code
                        i=int(status)

                        plist.append([pkt])
                       
                        
 

                    else:
                        pass

                    #print(f"{plist}\n\n")
                else:
                    pass




sniff(offline=filename, prn=func, store=False, session=TCPSession)

print(plist)
# filename="logfile.log"
# file=open(filename,'a')
# file.write(plist)
# file.close()








# for ip_src, mac_src,dst_src, type,
#print(plist[0])
from scapy.layers.inet import IP
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap

import csv
import pyshark
import sys
arguments = sys.argv



# from http import HTTPStatus

# Setting the colors
white = '\033[0m'
fail = red = '\033[91m'
success = green = '\033[92m'
yellow = '\033[93m'
blue = '\033[94m'

plist = []


filename = arguments[1]

print(f"{white}[ {green}OK {white}] Analyzing data packets http protocol")


packets = rdpcap(filename)
print(f"{white}[ {green}OK {white}] Capture has a total of: {yellow}{len(packets)} packets{white}")
print(f"{white}[ {green}OK {white}] Packet Analysis:")

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


# def pyshark_retran_packet(file):
#    capture = pyshark.FileCapture(file, display_filter='tcp.analysis.retransmission')
#    counter = 0
#    for packet in capture:
#        counter = counter + 1
#    return counter
# print("Total number of retransmitted frames found = ",pyshark_retran_packet(file) )

def pyshark_retran_packet(filename):
    capture = pyshark.FileCapture(filename, display_filter='tcp.analysis.retransmission')
    counter = 0
    final = ""
    for packet in capture:
        counter = counter + 1
        final = f"{white}[ {green}OK {white}]Total number of retransmitted frames found = {yellow}{str(counter)}"
    return final


print(pyshark_retran_packet(filename))
# pyshark_retran_packet(filename)

# define all possible http status codes
code = []
for i in range(100, 600):
    code.append(i)


# define list for report extracted from packets
unsorted_report = []
report = []


def func(pkt):
    # called on each packet
    stop = 0

    if HTTP in pkt and (HTTPResponse or HTTPResponse) in pkt:
        if HTTPResponse or HTTPRequest in pkt:
            # status codes are only in responses
            status = pkt[HTTPResponse].Status_Code or pkt[HTTPRequest]

            for status_code in code:
                if int(status_code) == int(status):
                    if (stop == 0):  # check code
                        print(f"""
                        {white}Source MAC: {green}{pkt.src}
                        {white}Source IP:  {green}{pkt[IP].src}
                        {white}Destination Mac: {green}{pkt.dst}
                        {white}Destination IP: {green}{pkt[IP].dst}
                        {white}Protocol: {green}http
                        {white}HTTP Status Code: {green}{pkt[HTTPResponse].Status_Code.decode()}
                        {white}Reason Phrase: {green}{pkt[HTTPResponse].Reason_Phrase.decode()}
                        {white}Date: {green}{pkt[HTTPResponse].Date}
                        """)

                        plist.append([pkt])
                        if pkt[HTTPResponse].Date == None:
                            time = None
                        else:
                            wakati = pkt[HTTPResponse].Date.decode()
                            # Fri, 07 May 2021 14:15:56 GMT
                            time = str(wakati)
                            # date = datetime.datetime(wakati)
                            # siku = (f"{date.year}-{date.month}-{date.day}")
                            # time = (f"{date.hour}:{date.minute}:{date.second}")
                        unsorted_report.append(
                            f"{pkt.src},{pkt[IP].src},{pkt.dst},{pkt[IP].dst},{pkt[TCP].sport},{(pkt[HTTPResponse].Status_Code).decode()},{(pkt[HTTPResponse].Reason_Phrase).decode()},{time}")




                    else:
                        pass

                    # print(f"{plist}\n\n")
                else:
                    pass


sniff(offline=filename, prn=func, store=False, session=TCPSession)

# filename="logfile.log"
# file=open(filename,'a')
# file.write(plist)
# file.close()


for x in unsorted_report:
    y = x.split(',')
    report.append(y)

# Define name of csv file to save data to and column names
csv_file = f"{filename}_http_report.csv"
csv_columns = ['dest_mac', 'dst_ip', 'src_mac', 'src_ip', 'protocol', 'status_code', 'reason_phrase', 'day', 'time']
with open(csv_file, "w") as csvfile:
    #writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    for column in csv_columns:
        csvfile.write(str(column) + ',')
    for row in report:
        csvfile.write('\n' + str(row) + ',')
    csvfile.write("\n")

print(f"{white}[ {green}OK {white}] Report generated and written to {yellow}{filename}_http_report.csv")
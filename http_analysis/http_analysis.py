from scapy.layers.inet import IP
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap

import csv
import pyshark
import sys

filename = sys.argv[2]
# from http import HTTPStatus

# Setting the colors
white = '\033[0m'
fail = red = '\033[91m'
success = green = '\033[92m'
yellow = '\033[93m'
blue = '\033[94m'

plist = []


print(f"{white}[ {green}OK {white}] Analyzing data packets http protocol")

#count number of packets
def rdp_caps(filename):
    packets = rdpcap(filename)
    print(f"{white}[ {green}OK {white}] Capture has a total of: {yellow}{len(packets)} packets{white}")

rdp_caps(filename)

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

if pyshark_retran_packet(filename) == None:
    print(f"{white}[ {green}OK {white}]Total number of retransmitted frames found = {yellow}0")
else:
    print(f"{pyshark_retran_packet(filename)}")
# pyshark_retran_packet(filename)


print(f"{white}[ {green}OK {white}] Packet Analysis:")

# define all possible http status codes
code = []
for i in range(100, 600):
    code.append(i)

# define list for report extracted from packets
#response packets
unsorted_report = []
report = []
#request packets
unsorted_request = []
request_report = []


def func(pkt):
    # called on each packet
    if (HTTP in pkt and HTTPRequest in pkt):
        print(f"""
        {white}Source MAC : {blue}{pkt.src}
        {white}Source IP : {blue}{pkt[IP].src}
        {white}Dst MAC : {blue}{pkt.dst}
        {white}Dst IP : {blue}{pkt[IP].dst}
        {white}Protocol : {blue}HTTP
        {white}Method : {blue}{pkt[HTTPRequest].Method.decode()}
        {white}Request Path : {blue}{pkt[HTTPRequest].Path.decode()}
        {white}Time : {blue}{pkt[HTTPRequest].If_Modified_Since}
        """)
        if pkt[HTTPRequest].If_Modified_Since == None:
            time = None
        else:
            wakati = pkt[HTTPRequest].If_Modified_Since.decode()
            time = str(wakati)
        unsorted_request.append(f"{pkt.src},{pkt[IP].src},{pkt.dst},{pkt[IP].dst},HTTP,{pkt[HTTPRequest].Method.decode()},{pkt[HTTPRequest].Path.decode()},{time}")
    
    #called on each packet
    stop = 0

    if HTTP in pkt and HTTPResponse in pkt:
        if HTTPResponse in pkt:
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
                        {white}HTTP Status
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




                    #else:
                    #    pass

                    # print(f"{plist}\n\n")
                #else:
                #    pass

sniff(offline=filename, prn=func, store=False, session=TCPSession)

#Requests Analysis
for y in unsorted_request:
    x = y.split(',')
    request_report.append(x)

# Define name of csv file to save data to and column names
csv_files = f"{filename}_Requests_http_report.csv"
csv_column = ['src_mac', 'src_ip', 'dest_mac', 'dst_ip', 'protocol', 'Method', 'Path', 'day', 'time']
with open(csv_files, "w") as csvfilez:
    #writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    for column in csv_column:
        csvfilez.write(str(column) + ',')
    for row in request_report:
        csvfilez.write('\n' + str(row) + ',')
    csvfilez.write("\n")


sniff(offline=filename, prn=func, store=False, session=TCPSession)

# filename="logfile.log"
# file=open(filename,'a')
# file.write(plist)
# file.close()


#Requests Analysis
for y in unsorted_request:
    x = y.split(',')
    request_report.append(x)

# Define name of csv file to save data to and column names
csv_files = f"{filename}_Requests_http_report.csv"
csv_column = ['src_mac', 'src_ip', 'dest_mac', 'dst_ip', 'protocol', 'Method', 'Path', 'day', 'time']
with open(csv_files, "w") as csvfilez:
    #writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    for column in csv_column:
        csvfilez.write(str(column) + ',')
    for row in request_report:
        csvfilez.write('\n' + str(row) + ',')
    csvfilez.write("\n")




#Responses analysis
for x in unsorted_report:
    y = x.split(',')
    report.append(y)

# Define name of csv file to save data to and column names
csv_file = f"{filename}_Responses_http_report.csv"
csv_columns = ['src_mac', 'src_ip', 'dst_mac', 'dst_ip', 'protocol', 'status_code', 'reason_phrase', 'day', 'time']
with open(csv_file, "w") as csvfile:
    #writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    for column in csv_columns:
        csvfile.write(str(column) + ',')
    for row in report:
        csvfile.write('\n' + str(row) + ',')
    csvfile.write("\n")

print(f"{white}[ {green}OK {white}] Requests report generated and written to {yellow}{filename}_Requests_http_report.csv")
print(f"{white}[ {green}OK {white}] Report generated and written to {yellow}{filename}_Responses_http_report.csv")
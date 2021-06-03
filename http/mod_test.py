import csv


#generate report
logfile="logfile.txt"
file=open(logfile,'r')
contents=file.read()



def cleandata(string):
    array=(string.split(' '))


    final={"dest_mac":array[2].split('=')[1],
    "src_mac":array[3].split('=')[1],
    "src_ip":array[17].split('=')[1],
    "dest_ip":array[18].split('=')[1],
    "protocol":array[21].split('=')[1],
    "status_code":array[43].split('=')[1],
    "reason_phrase":array[44].split('=')[1]}

    for item in final:
        value=final.get(item,"Not found")
        print(f"{item} : {value}")
    csv_columns = ['dest_mac','src_mac', 'src_ip', 'dest_ip', 'protocol', 'status_code', 'reason_phrase']
    csv_file = "http_packets_report.csv"

    try:
        for item in final:
            value=final.get(item,"Not Found")
        with open(csv_file,'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer = writer.writeheader()
            for item in final:
                value=final.get(item,"Not found")
                writer.writerow(f"{value}")
    except IOError:
        print("Input output error")



#cleandata(string)

array=(contents.split('[<Ether'))
final=[]
for item in array:
    result=(f"[<Ether{item}\n\n")
    final.append(result)

final=final[1:]

for line in final:
    cleandata(line)
    print('\n\n')
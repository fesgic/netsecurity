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
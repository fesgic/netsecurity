#!/usr/bin/python3
import sys
import os


if __name__ == "__main__":
    try:
        filename = sys.argv[1].strip()
        print(filename)
        if True:
            os.system('python3 http_analysis.py %s | tee logfile.txt' % filename)
            #os.system('python3 http_analysis.py %s | tee %s.txt' % (filename,filename ))
            os.system('python3 mod.py')

    except IndexError:
        print("[+] Usage: python3 %s <filename to analyze>" % sys.argv[0].strip())
        print("[-] Example: python3 %s http.pcap" % sys.argv[0].strip())
        sys.exit(-1)

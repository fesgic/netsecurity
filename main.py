#netsecurity
import sys


if __name__ == '__main__':
    try:
        argument1 = sys.argv[1].strip()
        argument2 = sys.argv[2].strip() 
        if str(argument1) == "-i":
            argument3 = sys.argv[3].strip()
            import capture.capture as packets_cap
            packets_cap.interface = argument2
            packets_cap.file = argument3
            packets_cap.packet_capture()
            packets_cap.permissions()
        elif str(argument1) == "-http":
            import http_analysis.http_analysis as http_analysis
            http_analysis.filename = argument2

    except IndexError:
        print("[+] NetSecurity")
        print("\t\t[+] Network Packet Capture")
        print("[-] Usage: sudo %s <-i> <interface> <filename to save to>" % sys.argv[0].strip())
        print("[-] Example: sudo %s -i vmnet8 capture.pcap       -    Capturing live traffic from the network" % sys.argv[0].strip())
        print("\n\t\t[+] HTTP Traffic Analysis")
        print("[-] Usage: python3 %s <-http> <filename to analyze>")
        print("[-] Example: python3 %s -http capture.pcap       - Perfom a http packet analsyis and generate report ")

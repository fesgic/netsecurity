#netsecurity
import sys

import capture.capture as packets_cap


if __name__ == '__main__':
    try:
        packets_cap.file = sys.argv[1].strip()
        if True:
            packets_cap.packet_capture()
    except IndexError:
        print("[-] Usage: %s <filename to save to>   " % sys.argv[0].strip())
        print("[-] Example: %s capture.pcap        -    Capturing traffic from the live network" % sys.argv[0].strip())


#netsecurity
import sys

import capture.capture as packets_cap

if __name__ == '__main__':
    try:
        packets_cap.packet_capture()
    except:
        None


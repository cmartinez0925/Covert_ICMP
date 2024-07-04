#Author: Chris Martinez
#Course: Covert Channels
#Date:   July 3, 2024
#Description: This scipt is similar to Project Loki, where we are using the
#             icmp echo to send covert data to a sender. That being said, it is
#             far more simpler... hey man never said I was a pro.




################################################################################
#IMPORTS - Gathering the troops
################################################################################
import argparse
import os
import sys
import time

from scapy.all import IP, ICMP, Raw, send, sniff


################################################################################
#FUNCTIONS
################################################################################
#Author: Chris Martinez
#Date: July 3, 2024 
#Description: Parses packet and determines if there is an ICMP field, and if so
#             check the type for an echo-request. If the packet contains both
#             the ICMP and the correct type, check if there is Raw data field 
#             and parse that data to print on the terminal
#Params: Packet
#Return: None
def process_packets(pkt):
    ECHO_REQUEST = 8

    try:
        if ICMP in pkt and pkt[ICMP].type == ECHO_REQUEST:
            if Raw in pkt:
                print(f"Received Message: {pkt[Raw].load.decode()}")
    except Exception as e:
        print(f"Error receiving message: {e}")


#Author: Chris Martinez
#Date: July 4, 2024 
#Description: Create ICMP packet with message and sends to the desire ip
#Params: src [IP ADDR you want to show as the source of the message]
#        dest [IP ADDR you want to send message to]
#        message [Desired message to be sent with packet]
#Return: None
def send_message(src, dst, message):
    try:
        pkt = IP(src=src, dst=dst)/ICMP()/message
        send(pkt)
        print(f"Message sent to {dst}")
    except Exception as e:
        print(f"Error sending message: {e}")

################################################################################
#MAIN() SCRIPT
################################################################################
#Author: Chris Martinez
#Date: July 3, 2024
#Description: Main Script
#Params: None
#Return: None
def main():
    ############################################################################
    #TERMINAL ARGUMENTS SETUP - Get data from user via the terminal
    ############################################################################
    parser = argparse.ArgumentParser(description="Covert ICMP")
    parser.add_argument("-s", "--src_ip", action="store", dest="src_ip", 
                        type=str, default='127.0.0.1', help="Source IP Address")
    parser.add_argument("-d", "--dest_ip", action="store", dest="dst_ip", 
                        type=str, required=True, help="Destination IP Address")
    parser.add_argument("-r", "--recieve", action="store_true", dest="reciever",
                        help="Run Script in Reciever Mode")
    parser.add_argument("-m", "--message", action="store", dest="message",
                        type=str, default="", help="Message to send")
    args = parser.parse_args()

    ############################################################################
    #CONSTANT VARIABLES - Thou shall not change
    ############################################################################
    VERSION = "1.0"
    SRC_ADDR = args.src_ip
    DEST_ADDR = args.dst_ip
    RECEIVING_DATA = args.reciever
    MESSAGE = args.message
    ROOT = 0
    
    #Lets get the party started
    print(f"Covert ICMP {VERSION} (Christopher E. Martinez (cmart104@jh.edu)")
    print("Covert Channel Assignment 2 - Covert ICMP using Scapy\n")

    #Only god can wield such power... him and root
    if os.geteuid() != ROOT:
        sys.exit("You need to be root to run this script.")

    ############################################################################
    #RECEIVING DATA - Do this if we are receiving the covert message
    ############################################################################
    if RECEIVING_DATA:
        print("Listening for ICMP traffic...")
        try:
            sniff(filter="icmp", prn=process_packets)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    ############################################################################
    #SENDING DATA - We do this if we are trying to send the covert message
    ############################################################################
    else:
        try:
            send_message(SRC_ADDR, DEST_ADDR, MESSAGE)
        except Exception as e:
            sys.exit(f"Error reading file: {e}")

if __name__ == '__main__':
    main()
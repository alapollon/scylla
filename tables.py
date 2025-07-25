from server import base 
from sqlalchemy import Column, Integer, String, Table, Select
import ip


class Main_Gateway_Scheme(Base):
    __tablename__= "main_gateway__scheme"
    id=Column("index", nullable=False)
    gateway_uuid: []= Column("uuid", unique=True, nullable=True)
    gate_cidr= Column("gateway",primary_key=True, nullable=True)
    gatewayipv4=Column("gateway4",primary_key=False, nullable=False)
    hops=Column("hops", nullable=False)
    vendor=Column("vendor", )
    os=Column()
    gateway_ipv6= Column("gatway6", unique= True, primary_key=True, nullable=False) 
    dname=Column("domain", primary_key=False , nullable= True )
    domain=Column("Company", unique=True, nullable=False )
    def __init__(self, args):
        self.ipv6=args.get["ipv6"]
        self.ipv4=args.get["ipv4"]
        self.domain=args.get["domain"]


class Node_Schema(Base):
    __tablename__= "node_edge_scheme"
    node_uuid: Mapped[]=Column("uuid",primary_key=True)
    mac=Column("mac",primary_key=True)
    layer=Column("layer")
    hops=Column("hops")
    cidr=Column("cidr",foreign_key=True,nullable=False)
    bgp=Column("layer")
    def __init__(self, *kwargs):
        self.layer=layer
        self.hop=hops
        self.cidr=cidr
        self.mac=

class Host_Schema(Base):
    __tablename__="hosts"
    id
    host_uuid=Column()
    mac=Column()
    os=Column()
    ipv4= 
    ipv6= 
    zone=
class Kansas_Cinncinati__Schema(Base):
    __tablename__="kansas_cincinnati__scheme"
    uuid: Mapped[]=Column("uuid",unique=True,primary_key=True,nullable=True)
    hops=Column( nullable=False)
    target_mac=Column(nullable=True)
    target_ipv6=Column()
    target_ipv4=Column()
    gatecid=Column("cidr",Binary(), nullable=False  )
    gateway=Column()
    gateway6: Mapped[]=Column(Primary_key=True, nullable=False )
    bgp=Column("bgp",Boolean(),)
    edges=Column("edges",Array(), nullable=False )
    port=("map",Array(), nullable=False)



class Edges_Table_Schema(Base):
    __tablename__="route_schemes"
    dst=Column("destination")
    gateway: mapped =Column("gateway")
    edges=Column( nullable=False )
    hostcount=Column( primary_key=True, nullable=False )
    nodecount=Column()
    pings=Column("hops", primary_key=True, nullable=False)
    tz=Column("timezones")


class Database_Table_Schema(Database):
    __tablename__="database_routes_schema"
    uuid=()
    hostipv6=Column()
    sub=Column()
    hostname=Column()
    url=Column()
    fitness=Column()
    masks=Column()

class Primary_Table_Schema(Base):
    __tablename__ = "mac_table__schema"
    @mapper_registry.as_declarative()
    id=Column("index", nulable=False)
    uuid=Column("uuid",primary_key=True)
    mac=Column("mac", primary_key=True)
    cidr=Column("cidr", nullable=True)
    category=Column("category")
    vendor=Column
    lastupdate=Column()  
    def transverse():
        pass 

    def __call__(self):
        pass 

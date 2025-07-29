import collections, re, hashlib, ftplib, multiprocessing, _multibytecodec, functools,
from scapy import *

def duplicate(packet):
    pass

def decode_icmp(packet):
    pass

def decode_dhcp(packet):
    ip=packet[IP].src
    pass

def decode_sftp(packet):
    parts=
    mac=packet.getlayer().src
    target=packet.getlayer(IP).dst
    raw=packet.sprintf('%Raw.load%')
    user=re.findall(f'',raw)
    password=re.finadll(f'',raw)
    try: 
        if user & password & raw:
            return mac, target, user, password, raw
    except Exception as e:
        if e:
            error=f"{e}"
            return ([error],[i for i in raw]) 


def decode_sshp(packet):
    pass 

def decode_ssl(packet):
    pass 

def decode_dns(packet):
    
    pass

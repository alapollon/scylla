import collections, re, hashlib, ftplib, multiprocessing, _multibytecodec, functools 
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
    while True:
        data={raw}
        if user & password :
            if parts > 1: 
                
            else :
                return data, user, password, target, mac
        else !user:
            try: 
                header=
                fingerprint= 
                return data, fingerprint, header
            except: 
                raise ...
                return 1
                pass


def decode_sshp(packet):
    pass 

def decode_ssl(packet):
    pass 

def decode_dns(packet):
    
    pass

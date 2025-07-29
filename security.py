import ssl, collections, iscertificate
from os.path import isfile, isdir, dirname, basename, listdir, exists

def transverse(path, keys)-> tuple:
        items_key=[]
        items=()
        items_count=1
        directory=[None]
        if exixts(path) & isdir(path):
            directory+=listdir(path)
            for item in directory:
                while isdir(item):
                    d2=listdir(item)
                    head=dirname(item)
                    keys+=head
                    items+=
                    items_count=len(items)
                    pass
                if isfile(item):
                    keys+=dirname(item)
                    items+=item
                    items_count+=1
                elif isfile(item) is False & isdir(item) is False:
                    continue
            return items, item_keys, items_count
        elif isfile(path):
            keys+=basename(path)
            return items, keys, items_count

class Securirty(ssl.SSLcontext):
    def __init__(self, psk=None):
        super().__init__(self)
        self.user_inputed_psk=psk 
        self.pool=namedtuple('Certificates', 'root, userServer, nonsort')
        pass

    def verify_server_certficates(self, path):
        psk=self.pool({},{},{})
        with path as ca:
            while ca:
                keys=list(psk.keys())
                items, item_keys, items_count=transverse(ca, keys)
                for ifcertificate in items:
                        index=dirname(ifcertificate)
                        if index in keys == False | index == "nonsorted" | isfile(ifcertificate):
                                try:
                                    certificate=iscertificate(ifcertificate)
                                    base=basename(ifcertificate)
                                    psk.nonsort[base]=certificate['identity']
                                except Exception as e:
                                    pass
                        elif index == "userServer":
                                try:
                                    certificate=iscertificate(ifcertificate)
                                    base=basename(ifcertificate)
                                    psk.userServer[base]=certificate['identity']
                                except Exception as e:
                                    pass
                        elif index == "root":
                            try:
                                certificate=iscertificate(ifcertificate)
                                base=basename(ifcertificate)
                                psk.root[base]=certificate['identity']
                            except Exception as e:
                                pass

     rootkey=property(lambda self: self.pool.root) 
     userkey=property(lambda self: self.pool.userServer)
     unsorted=property(lambda self: self.pool.nonsort) 


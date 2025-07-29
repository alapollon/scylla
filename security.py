import ssl, collections, iscertificate
from os.path import isfile, isdir, dirname, basename, listdir, exists

async def transverse(path, keys)-> tuple:
        key=[]
        items=()
        items_count=1
        directory=[None]
        if exixts(path) & isdir(path):
            directory+=listdir(path)
            for item in directory:
                while isdir(item):
                    head=dirname(item)
                    keys+=head
                    try: 
                        items+=sorted(listdir(item) )
                    except :
                        pass
                    items_count=len(items)
                    continue
                if isfile(item):
                    keys+=dirname(item)
                    items+=item
                    items_count+=1
                    continue
                elif isfile(item) is False & isdir(item) is False:
                    pass
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
        beta=asyncio.run
        with path as ca:
            while ca:
                items, item_keys, items_count=beta(transverse(ca, list(psk.keys())))
                for ifcertificate in items:
                        index=dirname(ifcertificate)
                        if index in list(psk.keys()) is False | isfile(ifcertificate):
                                try:
                                    certificate=iscertificate(ifcertificate)
                                    base=basename(ifcertificate)
                                    psk.nonsort[base]=certificate['identity']
                                except Exception as e:
                                    continue
                        elif index == "userServer":
                                try:
                                    certificate=iscertificate(ifcertificate)
                                    base=basename(ifcertificate)
                                    psk.userServer[base]=certificate['identity']
                                except Exception as e:
                                    continue
                        elif index == "root":
                            try:
                                certificate=iscertificate(ifcertificate)
                                base=basename(ifcertificate)
                                psk.root[base]=certificate['identity']
                            except Exception as e:
                                continue


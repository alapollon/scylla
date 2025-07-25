import ssl, collections, iscertificate
from os import path

class Securirty(ssl.SSLcontext):
    def __init__(self, args)
        super().__init__(self)
        self.path=args.get["path"]
        self.user_inputed_psk=args.get["psk"]
        self.pool=namedtuple('Certificates', 'root, userServer, nonsort')
        pass

    def verify_server_certficates(self):
        psk=self.pool({},{},{})
        with self.path as ca:
             if ca && path.isdir(ca):
                while True:
                    directory=os.listdir(ca)
                    for item in directory
                         if directory.count() == len(psk):
                            if path.isdir(item) & item != "root" | "userServer":
                                try:
                                    for ifcertificate in item:
                                        certificate=iscertificate(ifcertificate)
                                        if certificate['value']:
                                            base=path.basename
                                            psk.nonsort[base]=certificate['identity']
                                except Exception as e:
                                     pass
                            elif item == "root" & psk.index(root) is int:
                                try:
                                    certificate=iscertificate(item)
                                    name=path.basename
                                        if certificate['value'] & path.dirname(item) == "*root":
                                            psk.root[name]=certificate['identity']
                                            continue
                                except:
                                    pass
                            elif item == "userServer" & psk.index(userServer) is int:
                                try:
                                    certificate=iscertificate(item)
                                    name=path.basename
                                        if certificate['value'] & path.dirname(item) == "userServer":
                                            psk.root[name]=certificate['identity']
                                            continue
                                except:
                                    pass
                        elif directory.count() != len(psk):
                            try: 
                                certificate=iscertificate(item)
                                name=path.basename
                                key=[]
                                key+=list(psk.root.keys())
                                key+=list(psk.userServer.keys())
                                key+=list(psk.nonsort.keys())
                                if certificate['value'] & name != key.index[name]:
                                        psk.nonsort[file_name]=certificate['identity']
                            except:
                                pass
             elif path.isfile(ca):
                name=path.basename
                try:
                    psk.nonsort[name]=iscertificate(ca)['identity']
        except Exception as e:
            pass



import ssl, collections, iscertificate
from os.path import isfile, isdir, dirname, basename, listdir

class Securirty(ssl.SSLcontext):
        def __init__(self, psk=None):
            super().__init__(self)
            self.user_inputed_psk=psk 
            self.pool=namedtuple('Certificates', 'root, userServer, nonsort')
            pass

    def verify_server_certficates(self, path):
        psk=self.pool({},{},{})
        with path as ca:
             if ca && isdir(ca):
                while True:
                    directory=listdir(ca)
                    for item in directory:
                         if directory.count() == len(psk):
                            if isdir(item) & item != "root" | "userServer":
                                try:
                                    for ifcertificate in item:
                                        certificate=iscertificate(ifcertificate)
                                        base=basename(ifcertificate)
                                        if certificate['value']:
                                            psk.nonsort[base]=certificate['identity']
                                except Exception as e:
                                     pass
                            elif item == "root" & psk.index(root) is int:
                                try:
                                    if isfile(item):
                                        certificate=iscertificate(item)
                                        base=basename(item)
                                        if certificate['value'] & base == "root":
                                            psk.root[base]=certificate['identity']
                                            break
                                    else:
                                        for ifcertificate in item:
                                            certificate=iscertificate(ifcertificate)
                                            base=path.basename(ifcertificate)
                                            if certificate['value']:
                                                psk.root[base]=certificate(ifcertificate)
                                except:
                                    pass
                            elif item == "userServer" & psk.index(userServer) is int:
                                try:
                                    if isfile(item):
                                        certificate=iscertificate(item)
                                        base=basename(item)
                                        if certificate['value'] & isfile(item) & base == userServer:
                                            psk.userServer[name]=certificate['identity']
                                            break
                                        else:
                                            for ifcertificate in item:
                                                certificate=iscertificate(ifcertificate)
                                                base=basename(ifcertificate)
                                                if certificate['value'] & path.dirname(item) == "userServer":
                                                    psk.userServer[base]=certificate['identity']
                                except:
                                    pass
                        elif directory.count() != len(psk):
                            certificate=iscertificate(item)
                            try:
                                if certificate is:
                                name=basename
                                key=[]
                                key+=list(psk.root.keys())
                                key+=list(psk.userServer.keys())
                                key+=list(psk.nonsort.keys())
                                if certificate['value'] & name != key.index[name]:
                                        psk.nonsort[file_name]=certificate['identity']
                            except Exception as e:
                                pass
             elif isfile(ca):
                name=basename
                try:
                    psk.nonsort[name]=iscertificate(ca)['identity']
        except Exception as e:
            pass



import select, types, collections 

class Process(object):
    def __init__(self, task):
        self.task=task 
        self.value=0
        self.stack=[]
    def run():
        try:
            tax_value=self.task.send(self.value):
            if isinstance(task_value,SystemCall):
                return tax_value
            if isinstance(tax_value,types.GeneratorType)
                self.stack.append(self.target)
                self.sendval= None
                self.task= tax_value
            else:
                if not self.stack: return
                self.sendval= None 
                self.task= self.stack.pop()
            except StopIteration:
                if not self.stack: raise 
                self.sendval= None 
                self.task= self.stack.pop()

class ReadCoroutine(SystemCall):
    def __init__(self, file_descriptor):
        self.soc_ace=file_descriptor
    def handle(self, sched, task):
        fileno=self.soc_ace.fileno()
        sched.readwait(task, fileno)
        pass
class WriteCoroutine(SystemCall):
    def __init__(self, file_descriptor):
        self.soc_ace=file_descriptor
        pass
    def handle(self,sched, task):
        fileno=self.soc_ace.fileno()
        sched.writewait(task,fileno)
        pass
    

class CoSocket(object):
    def __init__(self, *args):
        soc, file=args 
        self.soc=soc
        self.file=file
    def bind(self,addr):
        yield self.soc.bind(addr) 
    def listen(self, backlog):
        yield self.soc.listen(bac)
    def connect(self,addr):
        yield WriteCoroutine(self.soc)
        yield self.soc.connect(addr)
    def accept(self):
        yield ReadWait(self.soc)
        conn, addr=self.soc.accept()
        yield CoSocket(conn), addr
    def send(self,data):
        while data: 
            evt= yield WriteCoroutine(self.soc)
    
read_coroutine=ReadCoroutine
write_corutine=ReadCoroutine



    
import collections, select, types

class Work(object):
    def __init__(self, target):
        self.target=target
        self.sendval=None 
        self.stack=[None]
        pass
    def start(self):
        try: 
            instance=self.target.send(self.sendval)
            if isinstance(instance, ):
                return instance
            elif isinstance(instance, types.GeneratorType):
                self.stack.append(self.target)
                self.sendval=None 
                self.target=instance
            else: 
                if not self.stack: return 
                self.sendval=None 
                self.target=self.stack.pop()
        except StopIteration:
            raise 

class Scheduler(object):
    def __init__(self):
        self.task_queqe= collections.deque()
        self.read_waiting= { }
        self.write_waiting= { }
        self.write_waiting= { }
        self.numtask= 0 

    def new(self,target):
        task= Work(object)
        self.schedule(task)
        self.numtasks+=1 
        pass

    def schedule(self,task):
        self.task_queqe.append(task)
        pass

    def read(self, task, fd): 
        try: 
            self.read_waiting[fd]= task
        except IOError and OSError: 
            pass 
    def write(self,task,fd):
        self.write_waiting[fd]= task
import psutil
import os

class ProcessManager:
    '''
    This class is designed to manage all processes, which will be used to start and kill
    green-cat, and take dump files
    '''
    def __init__(self):
        self.procDict = self.__pidDictBuilder__()

    def __pidDictBuilder__(self):
        '''
        This is used to build the process dict of {'name' : pid}
        '''
        procDict = {}
        pids = psutil.pids()
        for pid in pids:
            p = psutil.Process(pid)
            if not p.name():
                procDict[None] = pid
            else:
                process_name = p.name()
                procDict[process_name] = pid
        return procDict

    def showAllProcInfo(self):
        '''
        Show all process info: name and pid
        '''
        for process_name, pid in self.procDict.items():
            print(f'PID: {pid}, PROCESS NAME: {process_name}')

    def processKiller(self, name):
        '''
        Search and kill the process of given name
        '''
        flag = False
        for process_name, pid in self.procDict.items():
            if name == process_name:
                flag = True
                p = psutil.Process(pid)
                p.kill()
                print(f'{pid} killed.')
                break

        if not flag:
            print(f'Process Not Found: {name}')
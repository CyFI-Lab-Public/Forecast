from pygdbmi import gdbcontroller

class GDBManager:
    '''
    This class is designed to control GDB, which will be used to insert and/or remove breakpoint.
    It is a wrapper around pygdbmi.gdbcontroller
    '''
    def __init__(self):
        self.__controller = gdbcontroller.GdbController()
        self.__isActive = True

    def start():
        if not self.__isActive:
            self.__init__()

    def exec(self, command):
        output = self.__controller.write(command)
        return output
    
    def get_response(self):
        return self.__controller.get_gdb_response()

    def exit(self):
        if self.__isActive:
            self.__controller.exit()
            self.__isActive = False

        
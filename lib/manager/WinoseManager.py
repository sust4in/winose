try:
    import winappdbg
    import inspect
    import os
    from lib.core.core import Core
    from lib.core.logger import Logger
    from manager import WinoseManager
except ImportError, err:
    from lib.core.core import Core
    import winappdbg
    import inspect
    import os
    Core.print_error(err)

    __github__ = "https://github.com/canturk96/"
    __info__ = "An application layer network data sniffer"
    __author__ = "Ogulcan Gurcaglar"
    __version__ = "0.0.1"
    __date__ = "27/03/2016"


class EventHandler(winappdbg.EventHandler):
        """
        Event handler for win32 functions
        """

        def __init__(self,):
            winappdbg.EventHandler.__init__(self)
            self.hooks = hook_dict
        def load_dll(self, event):
            pid = event.get_pid()
            module = event.get_module()

            for dict_module_name in list(self.hooks.keys()):

                    #external dll function hooks.
                    values = self.hooks.get(dict_module_name)
                    for entry in values:
                        dict_module_function_name, dict_module_function = entry
                        if module.match_name(dict_module_name):
                                event.debug.hook_function(
                                    pid,
                                    module.resolve(dict_module_function_name),
                                    dict_module_function,
                                    paramCount=len(getargspec(dict_module_function)[0])-2
                                )


class Manager(object):
        def __init__(self,process):

                self.module_base_dict = {}
                self.name = process
                self.threads = {}
                self.hwnd = None
                self.hook_dict = {}
                self.base_address = None
                self.last_adress = None
                self.running = []

                if process is not None:
                    self.findProcess(process)
                    self.getBaseAdress()

        def __repr__(self):
                return "> Winose instance  : %s" %str(self.name)

        def findprocess(self, process):

                """
                self define for given process name
                """

                system = winappdbg.System()

                for system_process in system:
                        if system_process.get_filename() is not None:
                                name = system_process.get_filename().split("\\")[-1]

                                if name == process:
                                        self.hwnd = process
                                        break















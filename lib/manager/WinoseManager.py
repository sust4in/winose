try:
    import winappdbg
    import inspect
    import os
    from lib.core.core import Core
    from lib.core.logger import Logger
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


class BasicEventHandler(winappdbg.EventHandler):
        """
        Event handler for win32 functions
        """

        def __init__(self, hook_dict):
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
                                    paramCount=len(inspect.getargspec(dict_module_function)[0])-2
                                )


class Manager(object):
        def __init__(self, process):

                self.module_base_dict = {}
                self.name = process
                self.threads = {}
                self.hwnd = None
                self.hook_dict = {}
                self.base_address = None
                self.last_address = None
                self.running = []
                self.aim = "hook"

                if process is not None:
                        self.find_process(process)
                        self.get_base_address()

        def __repr__(self):
                return "> Winose instance  : %s" % str(self.name)

        def set_last_address(self):
                self.last_address = self.module_base_dict.get(
                        self.module_base_dict.keys()[::-1][0]
                )

        def find_process(self, process):

                """
                self define for given process name
                """

                system = winappdbg.System()
                system.request_debug_privileges()

                for system_process in system:
                        if system_process.get_filename() is not None:
                                name = system_process.get_filename().split("\\")[-1]

                                if name == process:
                                        self.hwnd = system.find_processes_by_filename(name)[0][0]
                                        break

        def get_base_address(self,):
                """
                this value stored in module_base_dict global variable
                """


                process = self.hwnd
                print "winose-> Process: %d <pid> %s <name>" % (process.get_pid(), self.name)

                # modules in the process
                print "Modules:"
                bits = process.get_bits()
                for module in process.iter_modules():
                        print "\t has module: %s\t%s" % (
                                winappdbg.HexDump.address(module.get_base(), bits),
                                module.get_filename()
                        )

                        if module.get_filename().split("\\")[-1] == self.name:
                                self.base_address = module.get_base()
                        else:
                                module_name = os.path.basename(module.get_filename())
                                self.module_base_dict[module_name] = module.get_base()

                if process is None:
                        raise ValueError, "Could not find process."

                try:
                        self.set_last_address()
                except IndexError, e:
                        pass

        def add_hook(self, module_name, function_name, function_handle):
                """Add hook to an external DLL function."""
                key = self.hook_dict.get(module_name)
                if key is not None:
                        key.append((function_name, function_handle))
                else:
                        self.hook_dict[module_name] = [(function_name, function_handle)]

        def hook(self):
                """Hook onto one or more of the processes module functions"""


                if self.hwnd is None:
                        raise ValueError, "You need to specify the process name"

                if len(self.hook_dict.keys()) == 0:
                        raise ValueError, "You currently haven't added any hooks!"
                debug = winappdbg.Debug(BasicEventHandler(self.hook_dict))

                try:
                        debug.attach(self.hwnd.get_pid())
                        debug.loop()
                finally:
                        debug.stop()




















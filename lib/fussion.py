try:
        import sys
        import time
        import subprocess
        from lib.core.core import Core
        from winappdbg import System
except ImportError, err:
        from lib.core.core import Core
        from winappdbg import System
        Core.print_error(err)


class Fussion(object):

        def __init__(self, args,__logger):
                self.__args = args
                _fuss_proc = self.__args.process
                system = System()
                proc = system.find_processes_by_filename(_fuss_proc)
                print proc











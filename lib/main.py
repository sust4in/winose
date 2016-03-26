try:
    import argparse
    from lib.core.core import Core
    from lib.core.logger import Logger
    from manager import WinoseManager
except ImportError, err:
    from lib.core.core import Core
    from manager import WinoseManager
    Core.print_error(err)

__version__ = '0.0.1-dev'
__banner__ = 'Winose v%s' % __version__


class Main(object):

        def __init__(self):

                usage = "usage for --help for further information"
                description = "use winose for sniffing application layer network packets"
                parser = argparse.ArgumentParser(description=description, usage=usage)

                parser.add_argument('-p', '--process', dest='process', action='store',
                                    help='Must enter specific process with .exe name example="iexplorer.exe" ',
                                    required=True)

                parser.add_argument('-l', '--log', dest='log_file', action='store', help='Log File',
                                    metavar='FILE', default="winose.log")

                parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose Output',
                                    default=None)

                try:
                    self.args = parser.parse_args()
                except Exception, err:
                    err

                try:
                    self.__logger = Logger(self.args.log_file, self.args.verbose)
                except Exception, err:
                    Core.print_error(err)

        def _run(self):
                try:
                    manager = WinoseManager()
                except Exception, err:
                    Core.print_error(err)
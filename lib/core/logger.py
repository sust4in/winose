import logging


class Logger(object):

        def __init__(self, logfile, verbose=False):

                logformatter = logging.Formatter("Winose -> %(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
                self.__rootLogger = logging.getLogger()
                self.__rootLogger.setLevel(logging.DEBUG)

                filehandler = logging.FileHandler(logfile)
                filehandler.setFormatter(logformatter)
                self.__rootLogger.addHandler(filehandler)

                if verbose:
                        consoleHandler = logging.StreamHandler()
                        consoleHandler.setFormatter(logformatter)
                        self.__rootLogger.addHandler(consoleHandler)

        def _logging(self, message):

                self.__rootLogger.debug(message)
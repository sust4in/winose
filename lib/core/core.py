import sys


class Core(object):

        @staticmethod
        def print_error(message):
                """ Print error message given """

                print >> sys.stderr, str(message)
                sys.exit(1)
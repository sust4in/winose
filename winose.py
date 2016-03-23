#!/usr/bin/python
try:
    from lib.main import Main
except ImportError, err:
    from lib.core.core import Core
    Core.print_error(err)

## open your eyes

if __name__ == "__main__":

    winose = Main()
    winose._run()

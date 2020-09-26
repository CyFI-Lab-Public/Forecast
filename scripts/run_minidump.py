import logging
import sys

import forsee
from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump

log = logging.getLogger(__name__)
'''
General usage of run_minidump.py is `python run_minidump.py ../path/to/saved/minidump arg1 val1 arg2 val2 ....`
Where arg1 val1, arg2 val2, etc are optional arguments that get added to the optional_args dictionary of an angr project.
'''
def main():
    logging.getLogger(forsee.__name__).setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)
    proj = None
    args = {}
    if len(sys.argv) > 2 and len(sys.argv) % 2 == 0:
        num_args = len(sys.argv)
        while num_args > 2:
            key = sys.argv[num_args - 2]
            value = sys.argv[num_args - 1]
            args[key] = value
            num_args -= 2
        proj = ForseeProjectMinidump(sys.argv[1], loop_bound=5, optional_args=args)
    elif len(sys.argv) == 2:
        proj = ForseeProjectMinidump(sys.argv[1], loop_bound=5)
    else:
        raise ValueError(
            "Usage: python run_minidump.py /path/to/mini.dmp or Usage: python run_minidump.py /path/to/mini.dmp opt_args (opt args come in pairs)"
        )
    explorer = Explorer(proj)
    explorer.run()


if __name__ == "__main__":
    main()
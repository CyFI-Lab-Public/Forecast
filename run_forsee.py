import logging

import forsee
from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump

log = logging.getLogger(__name__)


def main():
    logging.getLogger(forsee.__name__).setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)

    proj = ForseeProjectMinidump("sample_dumps/windows_dynamic_loading/Dump/Main.dmp")
    explorer = Explorer(proj)
    explorer.run()


if __name__ == "__main__":
    main()

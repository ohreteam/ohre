# The current version of ohre
__version__ = "0.0.1a"


import logging

from ohre.misc import Log
from ohre.core import oh_app
from ohre.core import oh_hap

Log.init_log("ohre_test", log_dir=".")
Log.debug(f"ohre __init__.py called")


def set_log_dir(log_dir: str):
    Log.init_log("ohre_test", log_dir)


def set_log_level(level: str):
    print(f"ohre setting log level {level}")
    g_log = Log.get_logger()
    if (level.lower() == "debug"):
        g_log.setLevel(logging.DEBUG)
    elif (level.lower() == "info"):
        g_log.setLevel(logging.INFO)
    elif (level.lower() == "warn"):
        g_log.setLevel(logging.WARNING)
    elif (level.lower() == "warning"):
        g_log.setLevel(logging.WARNING)
    elif (level.lower() == "error"):
        g_log.setLevel(logging.ERROR)
    else:
        print(f"ohre set log level ERROR, level not valid")


def set_log_print(print_flag: bool):
    print(f"ohre setting log console print flag {print_flag}")
    Log.set_debug_print_flag(print_flag)

set_log_print(False)
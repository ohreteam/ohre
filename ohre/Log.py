import logging
import os
from logging.handlers import RotatingFileHandler
import platform
import datetime

g_log = None
DEBUG_LOCAL = True
DEBUG_LEN = 500


def debug_print(logstr):
    if (DEBUG_LOCAL and len(logstr)):
        if (len(logstr) >= DEBUG_LEN):
            print("[LOG]", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), logstr[:DEBUG_LEN], " ... truncated")
        else:
            print("[LOG]", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), logstr)


def init_log(log_name: str):
    global g_log
    if (g_log is not None):
        return
    if (platform.system() == "Windows"):
        LOG_DIR = os.path.join("D:\\hre", "log")
    elif (platform.system() == "Linux"):
        LOG_DIR = os.path.join("/data", "hre", "log")
    elif (platform.system() == "Darwin"):
        LOG_DIR = os.path.join("/", "Users", "Shared", "hre", "log")
    else:
        print("NOT SUPPORTED OS")

    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    g_log = logging.getLogger(log_name)
    log_file = os.path.join(LOG_DIR, log_name + ".log")
    handle = RotatingFileHandler(log_file, mode="a", maxBytes=10 * 1024 * 1024,
                                 backupCount=10, encoding="utf-8", delay=0)
    g_log.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handle.setFormatter(formatter)
    g_log.addHandler(handle)
    return g_log


def get_logger():
    global g_log
    if g_log is None:
        return init_log("default_log_name")
    return g_log


def info(logstr, print_flag=True):
    if (print_flag):
        debug_print(logstr)
    g_log.info(logstr)


def warn(logstr, print_flag=True):
    if (print_flag):
        debug_print(logstr)
    g_log.warning(logstr)


def error(logstr, print_flag=True):
    if (print_flag):
        debug_print(logstr)
    g_log.error(logstr)


def debug(logstr, print_flag=True):
    if (print_flag):
        debug_print(logstr)
    g_log.debug(logstr)


if __name__ == "__main__":
    init_log("Log_TEST_started_from_main")

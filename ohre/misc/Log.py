import logging
import os
from logging.handlers import RotatingFileHandler
import platform
import datetime

g_log = None
DEBUG_LOCAL = True
DEBUG_LEN = 500


def debug_print(logstr: str, level: str = "debug"):
    if (DEBUG_LOCAL and len(logstr)):
        if (len(logstr) >= DEBUG_LEN):
            print("[LOG]", level, datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"), logstr[:DEBUG_LEN], " ... truncated")
        else:
            print("[LOG]", level, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), logstr)


def init_log(log_name: str, log_dir=""):
    global g_log
    if (platform.system() == "Windows"):
        LOG_DIR = os.path.join("D:\\ohre", "log")
    elif (platform.system() == "Linux"):
        LOG_DIR = os.path.join("/data", "ohre", "log")
    elif (platform.system() == "Darwin"):
        LOG_DIR = os.path.join("/", "Users", "Shared", "ohre", "log")
    else:
        print("Log init: NOT SUPPORTED OS")

    if (len(log_dir)):
        LOG_DIR = log_dir

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


def set_debug_print_flag(print_flag: bool):
    global DEBUG_LOCAL
    DEBUG_LOCAL = print_flag


def debug(logstr, print_flag=True):
    if (print_flag and get_logger().getEffectiveLevel() <= logging.DEBUG):
        debug_print(logstr, "debug")
    g_log.debug(logstr)


def info(logstr, print_flag=True):
    if (print_flag and get_logger().getEffectiveLevel() <= logging.INFO):
        debug_print(logstr, "info")
    g_log.info(logstr)


def warn(logstr, print_flag=True):
    if (print_flag and get_logger().getEffectiveLevel() <= logging.WARNING):
        debug_print(logstr, "warn")
    g_log.warning(logstr)


def error(logstr, print_flag=True):
    if (print_flag and get_logger().getEffectiveLevel() <= logging.ERROR):
        debug_print(logstr, "error")
    g_log.error(logstr)


def critical(logstr, print_flag=True):
    if (print_flag and get_logger().getEffectiveLevel() <= logging.CRITICAL):
        debug_print(logstr, "criti")
    g_log.critical(logstr)


if __name__ == "__main__":
    init_log("Log_TEST_started_from_main")

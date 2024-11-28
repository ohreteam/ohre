import argparse
import json
import os
import shutil
import sys
import time

import yara

import ohre
import ohre.abc_analyzer
import ohre.abc_analyzer.oh_abcbuf
import ohre.rules.filters_filename as filters_filename
from ohre.core import oh_app, oh_hap

if __name__ == "__main__":  # clear; pip install -e .; python3 abc_decompile.py a.abc
    parser = argparse.ArgumentParser()
    parser.add_argument("abc_path", type=str, help="path to abc file")
    arg = parser.parse_args()

    start_time = time.time()
    abc_path = arg.abc_path
    with open(abc_path,"rb") as f:
        buf = f.read()
        header = ohre.abc_analyzer.oh_abcbuf.AbcHeader(buf)
        f.close()

import argparse
import json
import os
import shutil
import sys
import time
import leb128
import yara

import ohre
import ohre.abc_decompiler.RegionHeader
import ohre.abc_decompiler.Header
import ohre.rules.filters_filename as filters_filename
from ohre.core import oh_app, oh_hap

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/abc_decompile.py a.abc
    parser = argparse.ArgumentParser()
    parser.add_argument("abc_path", type=str, help="path to abc file")
    arg = parser.parse_args()

    start_time = time.time()
    abc_path = arg.abc_path
    f = open(abc_path, "rb")
    buf = f.read()
    header = ohre.abc_decompiler.Header.Header(buf)
    print(f"> header.pos {header.pos} is_valid {header.is_valid()}")
    region_header = ohre.abc_decompiler.RegionHeader.RegionHeader(buf, header.pos)
    print(
        f"> region_header.pos {region_header.pos} start_off {hex(region_header.start_off)} proto_idx_off {hex(region_header.proto_idx_off)}")
    f.close()

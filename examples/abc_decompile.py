import argparse
import json
import os
import shutil
import sys
import time
import leb128
import yara

import ohre
import ohre.abc_decompiler.core.RegionHeader
import ohre.abc_decompiler.core.Header
import ohre.abc_decompiler.core.ClassIndex as ClassIndex
import ohre.abc_decompiler.core.Class as Class
import ohre.core.operator as op
from ohre.core import oh_app, oh_hap

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/abc_decompile.py a.abc
    parser = argparse.ArgumentParser()
    parser.add_argument("abc_path", type=str, help="path to abc file")
    arg = parser.parse_args()

    start_time = time.time()
    abc_path = arg.abc_path
    f = open(abc_path, "rb")
    buf = f.read()
    header = ohre.abc_decompiler.core.Header.Header(buf)
    print(f"> header.pos {header.pos} is_valid {header.is_valid()}")

    class_index = ClassIndex.ClassIndex(buf, header.class_idx_off, header.num_classes)
    print(f"> {class_index}")
    for offset in class_index.offsets:
        abc_class = Class.Class(buf,offset)
        print(f"> {abc_class}")

    print(f"header.pos value: {hex(op._read_uint32(buf, header.pos))}")
    for i in range(header.num_index_regions):
        region_header = ohre.abc_decompiler.core.RegionHeader.RegionHeader(buf, header.class_idx_off * 4)
        print(f"> {region_header}")
    f.close()

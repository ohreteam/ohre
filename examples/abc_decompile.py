import argparse
import os
import shutil
import sys
import time

import ohre
import ohre.abcre.core.RegionHeader
import ohre.abcre.core.Header
import ohre.abcre.core.ClassIndex as ClassIndex
import ohre.abcre.core.Class as Class
import ohre.core.operator as op
from ohre.core import oh_app, oh_hap
from ohre.misc import Log

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/abc_decompile.py a.abc
    ohre.set_log_level("info")
    ohre.set_log_print(True)
    parser = argparse.ArgumentParser()
    parser.add_argument("abc_path", type=str, help="path to abc file")
    arg = parser.parse_args()

    start_time = time.time()
    abc_path = arg.abc_path
    f = open(abc_path, "rb")
    buf = f.read()
    header = ohre.abcre.core.Header.Header(buf)
    print(f"> header.pos {header.pos} is_valid {header.is_valid()}")

    class_index = ClassIndex.ClassIndex(buf, header.class_idx_off, header.num_classes)
    print(f"> {class_index}")
    for i in range(len(class_index.offsets)):
        abc_class = Class.Class(buf, class_index.offsets[i])
        print(f">[{i}/{header.num_classes}] {abc_class} [abc_class print end]\n\n")

    # TODO: 2024.11.30 0250 finish class, then RegionHeader
    print(f"header.pos value: {hex(op._read_uint32(buf, header.pos))}")
    for i in range(header.num_index_regions):
        region_header = ohre.abcre.core.RegionHeader.RegionHeader(buf, header.class_idx_off * 4)
        print(f"> {region_header}")
    f.close()

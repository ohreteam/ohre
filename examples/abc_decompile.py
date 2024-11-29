import argparse
import time

import ohre
import ohre.abcre.core.RegionHeader
import ohre.abcre.core.Header
from ohre.abcre.core.ClassIndex import ClassIndex
from ohre.abcre.core.LineNumberProgramIndex import LineNumberProgramIndex
from ohre.abcre.core.LiteralArrayIndex import LiteralArrayIndex
from ohre.abcre.core.Class import Class
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

    class_index = ClassIndex(buf, header.class_idx_off, header.num_classes)
    print(f"> {class_index}")
    for i in range(len(class_index.offsets)):
        abc_class = Class(buf, class_index.offsets[i])
        print(f">[{i}/{header.num_classes}] {abc_class} [abc_class print end]\n")

    line_number_program_index = LineNumberProgramIndex(buf, header.lnp_idx_off, header.num_lnps)
    print(f"> {line_number_program_index}")

    literal_array_index = LiteralArrayIndex(buf, header.literalarray_idx_off, header.num_literalarrays)
    print(f"> {literal_array_index}")

    # TODO: RegionIndex
    # region_index = RegionIndex(buf, header.index_section_off, header.num_index_regions)
    # print(f"> {literal_array_index}")

    # TODO: 2024.11.30 0250 finish class, then RegionHeader
    print(f"header.pos value: {hex(op._read_uint32(buf, header.pos))}")
    for i in range(header.num_index_regions):
        region_header = ohre.abcre.core.RegionHeader.RegionHeader(buf, header.class_idx_off * 4)
        print(f"> {region_header}")
    f.close()

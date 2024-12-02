import argparse
import time

import ohre
import ohre.abcre.core.RegionHeader
import ohre.abcre.core.Header
from ohre.abcre.core.ClassIndex import ClassIndex
from ohre.abcre.core.LineNumberProgramIndex import LineNumberProgramIndex
from ohre.abcre.core.LiteralArrayIndex import LiteralArrayIndex
from ohre.abcre.core.RegionIndex import RegionIndex
from ohre.abcre.core.ClassRegionIndex import ClassRegionIndex
from ohre.abcre.core.MethodRegionIndex import MethodRegionIndex
from ohre.abcre.core.FieldRegionIndex import FieldRegionIndex
from ohre.abcre.core.ProtoRegionIndex import ProtoRegionIndex
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
    print(f"> {header} . is_valid {header.is_valid()}")

    class_index = ClassIndex(buf, header.class_idx_off, header.num_classes)
    print(f"> {class_index}")
    for i in range(len(class_index.offsets)):
        abc_class = Class(buf, class_index.offsets[i])
        print(f">> [{i}/{header.num_classes}] {abc_class}")

    line_number_program_index = LineNumberProgramIndex(buf, header.lnp_idx_off, header.num_lnps)
    print(f"> {line_number_program_index}")

    literal_array_index = LiteralArrayIndex(buf, header.literalarray_idx_off, header.num_literalarrays)
    print(f"> {literal_array_index}")

    region_index = RegionIndex(buf, header.index_section_off, header.num_index_regions)
    print(f"> {region_index}")
    for i in range(len(region_index.arrRegionHeader)):
        print(f">> [{i}/{len(region_index.arrRegionHeader)}]")
        class_region_index = ClassRegionIndex(
            buf, region_index.arrRegionHeader[i].class_idx_off, region_index.arrRegionHeader[i].class_idx_size)
        print(f">> {class_region_index}")
        method_region_index = MethodRegionIndex(
            buf, region_index.arrRegionHeader[i].method_idx_off, region_index.arrRegionHeader[i].method_idx_size)
        print(f">> {method_region_index}")
        field_region_index = FieldRegionIndex(
            buf, region_index.arrRegionHeader[i].field_idx_off, region_index.arrRegionHeader[i].field_idx_size)
        print(f">> {field_region_index}")
        proto_region_index = ProtoRegionIndex(
            buf, region_index.arrRegionHeader[i].proto_idx_off, region_index.arrRegionHeader[i].proto_idx_size)
        print(f">> {proto_region_index}")

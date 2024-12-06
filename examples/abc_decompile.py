import argparse
import time

import ohre
import ohre.abcre.core.Header
import ohre.abcre.core.RegionHeader
import ohre.core.operator as op
from ohre.abcre.core.Class import Class
from ohre.abcre.core.ClassIndex import ClassIndex
from ohre.abcre.core.ClassRegionIndex import ClassRegionIndex
from ohre.abcre.core.FieldRegionIndex import FieldRegionIndex
from ohre.abcre.core.ForeignMethod import ForeignMethod
from ohre.abcre.core.LineNumberProgramIndex import LineNumberProgramIndex
from ohre.abcre.core.LiteralArray import LiteralArray
from ohre.abcre.core.LiteralArrayIndex import LiteralArrayIndex
from ohre.abcre.core.MethodRegionIndex import MethodRegionIndex
from ohre.abcre.core.ProtoRegionIndex import ProtoRegionIndex
from ohre.abcre.core.RegionIndex import RegionIndex
from ohre.core import oh_app, oh_hap
from ohre.misc import Log

if __name__ == "__main__":  # clear; pip install -e .; python3 examples/abc_decompile.py a.abc
    Log.init_log("abcre", ".")
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
    # Offset to the foreign region.
    # The region must contain elements only of types ForeignField, ForeignMethod, or ForeignClass.
    # It is not necessary foreign_off points to the first entity.
    # Runtime should use foreign_off and foreign_size to determine type of an offset.
    print(f"> header.foreign_off {header.foreign_off} header.foreign_size {header.foreign_size}")
    class_index = ClassIndex(buf, header.class_idx_off, header.num_classes)
    print(f"> {class_index}")
    Method_addr_l = list()
    for i in range(len(class_index.offsets)):
        abc_class = Class(buf, class_index.offsets[i])
        print(f">> [{i}/{header.num_classes}] {abc_class}")
        for method in abc_class.methods:
            Method_addr_l.append(method.get_pos_start())
    Method_addr_l = sorted(Method_addr_l)

    line_number_program_index = LineNumberProgramIndex(buf, header.lnp_idx_off, header.num_lnps)
    print(f"> {line_number_program_index}")

    literal_array_index = LiteralArrayIndex(buf, header.literalarray_idx_off, header.num_literalarrays)
    print(f"> {literal_array_index}")
    literal_array_d = dict()
    for i in range(len(literal_array_index.offsets)):
        la = LiteralArray(buf, literal_array_index.offsets[i])
        print(f">> [{i}/{len(literal_array_index.offsets)}] {la}")
        literal_array_d[la.get_pos_start()] = la.num_literals
    literal_array_d = dict(sorted(literal_array_d.items()))
    out = ""
    for k, v in literal_array_d.items():
        out += f"{hex(k)} {hex(v)}, "
    print(f">>> debug >>> literal_array_d({len(literal_array_d)}) {out}")
    exit()

    region_index = RegionIndex(buf, header.index_section_off, header.num_index_regions)
    print(f"\n> RegionIndex: {region_index}")
    method_in_MethodRegionIndex_l = list()
    for i in range(len(region_index.arrRegionHeader)):
        print(f">> [{i}/{len(region_index.arrRegionHeader)}] region_index.arrRegionHeader")
        class_region_index = ClassRegionIndex(
            buf, region_index.arrRegionHeader[i].class_idx_off, region_index.arrRegionHeader[i].class_idx_size)
        print(f">> {class_region_index}")

        method_region_index = MethodRegionIndex(
            buf, region_index.arrRegionHeader[i].method_idx_off, region_index.arrRegionHeader[i].method_idx_size)
        for method_off in method_region_index.offsets:
            method_in_MethodRegionIndex_l.append(method_off)
        print(f">> {method_region_index}")
        # for off in method_region_index.offsets: # TODO: it's weird! some seems like a String
        #     print(f"off {hex(off)}")
        #     foreign_method = ForeignMethod(buf, off)
        #     print(f">>>> {foreign_method}")

        field_region_index = FieldRegionIndex(
            buf, region_index.arrRegionHeader[i].field_idx_off, region_index.arrRegionHeader[i].field_idx_size)
        print(f">> {field_region_index}")

        proto_region_index = ProtoRegionIndex(
            buf, region_index.arrRegionHeader[i].proto_idx_off, region_index.arrRegionHeader[i].proto_idx_size)
        print(f">> {proto_region_index}")

    out = f"len {len(Method_addr_l)}: "
    for addr in Method_addr_l:
        out += f"{hex(addr)} "
    print(f"{out} Method_addr_l")

    out = f"len {len(method_in_MethodRegionIndex_l)}: "
    for addr in method_in_MethodRegionIndex_l:
        out += f"{hex(addr)} "
    print(f"{out} method_in_MethodRegionIndex_l")

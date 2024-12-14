import argparse
import time

import ohre
import ohre.abcre.core.Header
import ohre.abcre.core.IndexHeader
import ohre.core.ohoperator as op
from ohre.abcre.core.Class import Class
from ohre.abcre.core.ClassIndex import ClassIndex
from ohre.abcre.core.ClassRegionIndex import ClassRegionIndex
from ohre.abcre.core.FieldRegionIndex import FieldRegionIndex
from ohre.abcre.core.ForeignMethod import ForeignMethod
from ohre.abcre.core.LineNumberProgramIndex import LineNumberProgramIndex
from ohre.abcre.core.LiteralArray import LiteralArray
from ohre.abcre.core.LiteralArrayIndex import LiteralArrayIndex
from ohre.abcre.core.MethodStringLiteralRegionIndex import MethodStringLiteralRegionIndex
from ohre.abcre.core.ProtoRegionIndex import ProtoRegionIndex
from ohre.abcre.core.IndexSection import IndexSection
from ohre.core import oh_app, oh_hap
from ohre.abcre.ArkTSAnalyzer import ArkTSAnalyzer
from ohre.misc import Log
from ohre.abcre.enum.MethodTag import MethodTag
from ohre.abcre.core.DebugInfo import DebugInfo
from ohre.abcre.core.Annotation import Annotation

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
    class_index = ClassIndex(buf, header.class_region_idx_off, header.num_classes)
    print(f"> {class_index}")
    for i in range(len(class_index.offsets)):
        abc_class = Class(buf, class_index.offsets[i])
        print(f">> [{i}/{header.num_classes}] {abc_class}")
        # Fetch DeBugInfo
        for method_ in abc_class.methods:
            for t_v in method_.method_data:
                if t_v.tag == MethodTag.DEBUG_INFO:
                    debuginfo = DebugInfo(buf, t_v.data)
                    print(f" >>> {debuginfo}")
                if t_v.tag == MethodTag.ANNOTATION:
                    annotation = Annotation(buf, op._uint8_t_array_to_int(t_v.data))
                    print(f" >>> {annotation}")
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

    region_index = IndexSection(buf, header.index_section_off, header.num_index_regions)
    print(f"\n> IndexSection: {region_index}")
    for i in range(len(region_index.headers)):
        print(f">> [{i}/{len(region_index.headers)}] region_index.headers")
        class_region_index = ClassRegionIndex(
            buf, region_index.headers[i].class_region_idx_off, region_index.headers[i].class_region_idx_size)
        print(f">> {class_region_index}")

        method_region_index = MethodStringLiteralRegionIndex(
            buf, region_index.headers[i].method_string_literal_region_idx_off, region_index.headers[i].method_string_literal_region_idx_size)
        print(f">> {method_region_index}")

        field_region_index = FieldRegionIndex(
            buf, region_index.headers[i].field_idx_off, region_index.headers[i].field_idx_size)
        print(f">> {field_region_index}")

        proto_region_index = ProtoRegionIndex(
            buf, region_index.headers[i].proto_idx_off, region_index.headers[i].proto_idx_size)
        print(f">> {proto_region_index}")

    print(f"\n\n=== ArkTSAnalyzer START =========================")
    arkts_analyzer = ArkTSAnalyzer(buf)
    print(f"=== ArkTSAnalyzer END =========================\n\n")
    for k, v in arkts_analyzer.methods_in_ri.items():
        print(f"> method-ri > {hex(k)} \t: {v}")

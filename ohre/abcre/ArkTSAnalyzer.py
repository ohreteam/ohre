import argparse
import time
from typing import Any, Dict, Iterable, List, Tuple

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
from ohre.abcre.core.String import String

from ohre.core import oh_app, oh_hap
from ohre.misc import Log


class ArkTSAnalyzer:
    def __init__(self, buf):
        self.buf = buf
        self.header = ohre.abcre.core.Header.Header(buf)
        self.class_index = ClassIndex(buf, self.header.class_idx_off, self.header.num_classes)
        self.line_number_program_index = LineNumberProgramIndex(buf, self.header.lnp_idx_off, self.header.num_lnps)
        self.literal_array_index = LiteralArrayIndex(
            buf, self.header.literalarray_idx_off, self.header.num_literalarrays)
        self.literal_array_map: Dict[int, LiteralArray] = dict()
        for i in range(len(self.literal_array_index.offsets)):
            la = LiteralArray(buf, self.literal_array_index.offsets[i])
            self.literal_array_map[self.literal_array_index.offsets[i]] = la

        self.region_index = RegionIndex(buf, self.header.index_section_off, self.header.num_index_regions)
        self.class_region_indexes: Dict[int, ClassRegionIndex] = dict()
        self.method_region_indexes: Dict[int, MethodRegionIndex] = dict()
        for i in range(len(self.region_index.arrRegionHeader)):
            class_region_index = ClassRegionIndex(
                buf, self.region_index.arrRegionHeader[i].class_idx_off,
                self.region_index.arrRegionHeader[i].class_idx_size)
            self.class_region_indexes[i] = class_region_index

            method_region_index = MethodRegionIndex(
                buf, self.region_index.arrRegionHeader[i].method_idx_off,
                self.region_index.arrRegionHeader[i].method_idx_size)
            self.method_region_indexes[i] = method_region_index

            field_region_index = FieldRegionIndex(
                buf, self.region_index.arrRegionHeader[i].field_idx_off,
                self.region_index.arrRegionHeader[i].field_idx_size)
            proto_region_index = ProtoRegionIndex(
                buf, self.region_index.arrRegionHeader[i].proto_idx_off,
                self.region_index.arrRegionHeader[i].proto_idx_size)\


        # === the following code is just for debug ========================================
        self.classes_in_class_index = dict()  # key: offset, value: panda Class
        self.method_in_class_index = dict()  # key: offset,
        for i in range(len(self.class_index.offsets)):
            abc_class = Class(buf, self.class_index.offsets[i])
            for method in abc_class.methods:
                self.method_in_class_index[method.get_pos_start()] = method
            self.classes_in_class_index[self.class_index.offsets[i]] = abc_class

        # ri is short for region index
        self.methods_in_ri = dict()  # key: offset; value: Method / String / LiteralArray
        for method_region_index in self.method_region_indexes.values():
            for off in method_region_index.offsets:
                if (off in self.method_in_class_index.keys()):
                    self.methods_in_ri[off] = self.method_in_class_index[off]
                elif (off in self.literal_array_map.keys()):
                    self.methods_in_ri[off] = self.literal_array_map[off]
                else:
                    self.methods_in_ri[off] = String(self.buf, off)

    def get_region_index_len(self):
        return self.header.num_index_regions

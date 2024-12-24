from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.enum.FunctionKind import FunctionKind
import ohre.misc.const as const


class ForeignMethod(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        # an offset to a Class or a ForeignClass
        self.class_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.reserved0, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.name_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.name = op._read_String(buf, self.name_off)
        # MethodIndexData # unsigned 32bit int saved as a uleb128
        self.index_data, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)

    def __str__(self):
        out = f"ForeignMethod: [{hex(self.pos_start)}/{hex(self.pos_end)}] {self.name} class_idx {hex(self.class_idx)} \
reserved0 {hex(self.reserved0)} name_off {hex(self.name_off)} index_data {MethodIndexData(self.index_data)}"
        return out


class MethodIndexData():
    def __init__(self, int: int):
        self.header_index = int & const.UINT16MAX
        self.function_kind = int >> 16 & const.UINT8MAX
        self.reserved = int >> 24 & const.UINT8MAX

    def __str__(self):
        out = f"{hex(self.header_index)}|{FunctionKind.get_code_name(self.function_kind)}|{hex(self.reserved)}"
        return out

from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.ForeignMethod import ForeignMethod


class MethodStringLiteralRegionIndex(BaseRegion):
    def __init__(self, buf, pos: int, method_string_literal_region_idx_size: int):
        pos = op._align4(pos)
        super().__init__(pos)
        self.offsets: List[int] = list()  # uint32_t[] # Array of offsets to Method or ForeignMethod structures
        if (method_string_literal_region_idx_size <= 0
                or method_string_literal_region_idx_size == op._get_uint32_t_max()):
            return
        for _ in range(method_string_literal_region_idx_size):
            # TODO: determine if it's Method or ForeignMethod
            offs, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(offs)
        assert len(self.offsets) == method_string_literal_region_idx_size

    def __str__(self):
        out_offsets = ""
        for i in range(len(self.offsets)):
            out_offsets += f"{hex(self.offsets[i])} "
        out = f"MethodStringLiteralRegionIndex({hex(len(self.offsets))}): [{hex(self.pos_start)}/{hex(self.pos_end)}] \
{out_offsets}"
        return out

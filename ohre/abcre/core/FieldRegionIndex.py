from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class FieldRegionIndex(BaseRegion):
    def __init__(self, buf, pos: int, field_idx_size: int):
        pos = op._align4(pos)
        super().__init__(pos)
        self.offsets: List[int] = list()  # uint32_t[] # Array of offsets to Field or ForeignField structures
        if (field_idx_size <= 0 or field_idx_size == op._get_uint32_t_max()):
            return
        for i in range(field_idx_size):
            # TODO: determine if it's Field or the ForeignField
            offs, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(offs)

    def __str__(self):
        out_offsets = ""
        for i in range(len(self.offsets)):
            out_offsets += f"{hex(self.offsets[i])} "
        out = f"FieldRegionIndex({hex(len(self.offsets))}): [{hex(self.pos_start)}/{hex(self.pos_end)}] {out_offsets}"
        return out

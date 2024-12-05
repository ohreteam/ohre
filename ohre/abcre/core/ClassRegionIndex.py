import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.FieldType import FieldType

from typing import Any, Dict, List, Tuple, Iterable


class ClassRegionIndex(BaseRegion):
    def __init__(self, buf, pos: int, class_idx_size: int):
        pos = op._align4(pos)
        super().__init__(pos)
        self.types: List[FieldType] = list()
        if (class_idx_size <= 0 or class_idx_size == op._get_uint32_t_max()):
            return
        for i in range(class_idx_size):
            ft, self.pos_end = FieldType._get_class_offset(buf, self.pos_end)
            self.types.append(ft)

    def __str__(self):
        out_types = ""
        for i in range(len(self.types)):
            out_types += f"{self.types[i]} "
        out = f"ClassRegionIndex({hex(len(self.types))}): [{hex(self.pos_start)}/{hex(self.pos_end)}] {out_types}"
        return out

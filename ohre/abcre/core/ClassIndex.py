from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class ClassIndex(BaseRegion):
    def __init__(self, buf, pos: int, num_classes: int = 0):
        pos = op._align4(pos)
        super().__init__(pos)
        self.offsets: List[int] = list()
        for i in range(num_classes):
            tmp, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(tmp)
        assert len(self.offsets) == num_classes

    def __str__(self):
        out = f"ClassIndex: [{hex(self.pos_start)}/{hex(self.pos_end)}] offsets({hex(len(self.offsets))})"
        for v in self.offsets:
            out += f" {hex(v)}"
        return out

    def debug_deep(self):
        # TODO: implement debug_deep in Class
        pass

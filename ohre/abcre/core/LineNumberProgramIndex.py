from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class LineNumberProgramIndex(BaseRegion):
    def __init__(self, buf, pos: int, num_lnps: int = 0):
        super().__init__(pos)
        self.offsets: List[int] = list()
        for _ in range(num_lnps):
            tmp, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(tmp)
        assert len(self.offsets) == num_lnps

    def __str__(self):
        out = f"LineNumberProgramIndex: [{hex(self.pos_start)}/{hex(self.pos_end)}] offsets({hex(len(self.offsets))})"
        for v in self.offsets:
            out += f" {hex(v)}"
        return out

from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class LiteralArray(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        # num of literals that a literalarray has
        self.num_literals, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.literals, self.pos_end = "", self.pos_end  # op._read_literal(buf, self.pos_end)

    def __str__(self):
        out = f"LiteralArray: [{hex(self.pos_start)}/{hex(self.pos_end)}] \
num_literals {hex(self.num_literals)} literals {self.literals}"
        return out

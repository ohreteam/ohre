import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from typing import Any, Dict, List, Tuple


class ForeignClass(BaseRegion):
    def __init__(self, buf=None, pos: int = 0):
        super().__init__(pos)
        if (buf is not None):
            self.name, self.pos_end = op._read_String_offset(buf, self.pos_end)

    def __str__(self):
        out = f"{self.name}"
        return out

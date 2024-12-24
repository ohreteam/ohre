from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class ForeignClass(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        if (buf is not None):
            self.name, self.pos_end = op._read_String_offset(buf, self.pos_end)

    def __str__(self):
        out = f"{self.name}"
        return out

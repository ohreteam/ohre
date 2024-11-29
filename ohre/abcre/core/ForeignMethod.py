import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from typing import Any, Dict, List, Tuple


class ForeignMethod(BaseRegion):
    def __init__(self, buf=None, pos: int = 0):
        super().__init__(pos)
        if (buf is not None):
            self.class_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            self.proto_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            self.name_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.access_flags, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)

    def __str__(self):
        out = f"ForeignMethod: [{hex(self.pos_start)}/{hex(self.pos_end)}] class_idx {hex(self.class_idx)} \
type_idx {hex(self.type_idx)} name_off {hex(self.name_off)} access_flags {hex(self.access_flags)}"
        return out

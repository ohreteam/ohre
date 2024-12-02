import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class LiteralArrayIndex(BaseRegion):
    def __init__(self, buf, pos: int = 0, num_lnps: int = 0):
        pos = op._align4(pos)
        super().__init__(pos)
        self.offsets = list()
        for i in range(num_lnps):
            tmp, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(tmp)

    def __str__(self):
        out = f"LiteralArrayIndex: [{hex(self.pos_start)}/{hex(self.pos_end)}] offsets({hex(len(self.offsets))})"
        for v in self.offsets:
            out += f" {hex(v)}"
        return out

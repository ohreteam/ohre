import ohre.core.operator as op
import ohre.abc_decompiler.core.BaseRegion as BaseRegion

class ClassIndex(BaseRegion.BaseRegion):
    def __init__(self, buf, pos: int = 0, num_classes: int = 0):
        super().__init__(pos)
        self.offsets = list()
        for i in range(num_classes):
            tmp, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.offsets.append(tmp)

    def __str__(self):
        out = f"ClassIndex: pos start/end {hex(self.pos_start)}/{hex(self.pos_end)} num_classes {hex(len(self.offsets))}"
        for v in self.offsets:
            out += f" {hex(v)}"
        return out

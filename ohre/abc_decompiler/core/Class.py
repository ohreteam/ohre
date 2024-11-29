import ohre.core.operator as op
import ohre.abc_decompiler.core.BaseRegion as BaseRegion

class Class(BaseRegion.BaseRegion):
    def __init__(self, buf, pos: int = 0):
        super().__init__(pos)
        self.name, self.pos_end = op._read_TypeDescriptor_offset(buf, self.pos_end)
    
    def __str__(self):
        out = f"Class: pos start/end {hex(self.pos_start)}/{hex(self.pos_end)} name {self.name}"
        return out

import ohre.core.operator as op
import ohre.abc_decompiler.core.BaseRegion as BaseRegion

class RegionHeader(BaseRegion.BaseRegion):
    def __init__(self, buf, pos: int = 0):
        super().__init__(pos)
        self.buf = buf

        self.start_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.end_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.class_idx_size, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.class_idx_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.method_idx_size, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.method_idx_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.field_idx_size, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.field_idx_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.proto_idx_size, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)
        self.proto_idx_off, self.pos_end = op._read_uint32_t_offset(self.buf, self.pos_end)

    def __str__(self):
        return f"""RegionHeader: pos start/pos {hex(self.pos_start)}/{hex(self.pos_end)} start_off/end_off {hex(self.start_off)}/{hex(self.end_off)} class_idx_size/class_idx_off {hex(self.class_idx_size)}/{hex(self.class_idx_off)}\nmethod_idx_size/method_idx_off {hex(self.method_idx_size)}/{hex(self.method_idx_off)} field_idx_size/field_idx_off {hex(self.field_idx_size)}/{hex(self.field_idx_off)} proto_idx_size/proto_idx_off {hex(self.proto_idx_size)}/{hex(self.proto_idx_off)}"""

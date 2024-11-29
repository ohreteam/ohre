import ohre.core.operator as op


class RegionHeader:
    def __init__(self, buf, pos: int = 0):
        self.pos = pos
        self.buf = buf

        self.start_off, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.end_off, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.class_idx_size, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.class_idx_off, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.method_idx_size, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.method_idx_off, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.field_idx_size, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.field_idx_off, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.proto_idx_size, self.pos = op._read_uint32_offset(self.buf, self.pos)
        self.proto_idx_off, self.pos = op._read_uint32_offset(self.buf, self.pos)

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class IndexHeader(BaseRegion):
    def __init__(self, buf, pos: int):
        pos = op._align4(pos)
        super().__init__(pos)

        self.start_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.end_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.class_region_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the class index structure # ClassRegionIndex
        self.class_region_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.method_string_literal_region_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the method index structure # MethodStringLiteralRegionIndex
        self.method_string_literal_region_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        # reserved
        self.field_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.field_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.proto_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.proto_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

    def __str__(self):
        out = f"IndexHeader: [{hex(self.pos_start)}/{hex(self.pos_end)}] \
start_off/end_off {hex(self.start_off)}/{hex(self.end_off)} \
class_region_idx_size/class_region_idx_off {hex(self.class_region_idx_size)}/{hex(self.class_region_idx_off)} \
method_string_literal_region_idx_size/method_string_literal_region_idx_off \
{hex(self.method_string_literal_region_idx_size)}/{hex(self.method_string_literal_region_idx_off)} \
field_idx_size/field_idx_off {hex(self.field_idx_size)}/{hex(self.field_idx_off)} \
proto_idx_size/proto_idx_off {hex(self.proto_idx_size)}/{hex(self.proto_idx_off)}"
        return out

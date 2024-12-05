import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class RegionHeader(BaseRegion):
    def __init__(self, buf, pos: int):
        pos = op._align4(pos)
        super().__init__(pos)

        self.start_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.end_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.class_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the class index structure # ClassRegionIndex
        self.class_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.method_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the method index structure # MethodRegionIndex
        self.method_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.field_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the field index structure # FieldRegionIndex
        self.field_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

        self.proto_idx_size, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        # Offset to the proto index structure. # ProtoRegionIndex
        self.proto_idx_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

    def __str__(self):
        out = f"RegionHeader: [{hex(self.pos_start)}/{hex(self.pos_end)}] \
start_off/end_off {hex(self.start_off)}/{hex(self.end_off)} \
class_idx_size/class_idx_off {hex(self.class_idx_size)}/{hex(self.class_idx_off)} \
method_idx_size/method_idx_off {hex(self.method_idx_size)}/{hex(self.method_idx_off)} \
field_idx_size/field_idx_off {hex(self.field_idx_size)}/{hex(self.field_idx_off)} \
proto_idx_size/proto_idx_off {hex(self.proto_idx_size)}/{hex(self.proto_idx_off)}"
        return out

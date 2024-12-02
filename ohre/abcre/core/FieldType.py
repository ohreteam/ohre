import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion


class FieldType(BaseRegion):
    d_code_to_type = {
        0x00: "u1",
        0x01: "i8",
        0x02: "u8",
        0x03: "i16",
        0x04: "u16",
        0x05: "i32",
        0x06: "u32",
        0x07: "f32",
        0x08: "f64",
        0x09: "i64",
        0x0a: "u64",
        0x0b: "any",
    }
    u1 = 0x00
    i8 = 0x01
    u8 = 0x02
    i16 = 0x03
    u16 = 0x04
    i32 = 0x05
    u32 = 0x06
    f32 = 0x07
    f64 = 0x08
    i64 = 0x09
    u64 = 0x0a
    any = 0x0b

    def __init__(self, buf, pos: int):
        super().__init__(pos)
        # must by a uint32_t
        self.field_type, self.pos_end = op._read_uint32_t_offset(buf, pos)

    def field_type_name(self) -> str:
        if (self.field_type in self.d_code_to_type.keys()):
            return self.d_code_to_type[self.field_type]
        else:
            return None

    def __str__(self):
        if (self.field_type_name() is None):
            return f"{hex(self.field_type)}"
        else:
            return f"{hex(self.field_type)}({self.field_type_name()})"

import leb128
import ohre.core.operator as op
import ohre.abc_decompiler.core.BaseRegion as BaseRegion
# https://gitee.com/openharmony/arkcompiler_runtime_core/blob/master/docs/file_format.md#string


class String(BaseRegion.BaseRegion):
    def __init__(self, buf, pos: int = 0):
        super().__init__(pos)
        self.utf16_length, readed_bytes = leb128.u.decode_reader(buf, pos)
        self.pos_end += readed_bytes
        self.data, self.pos_end = op._read_uint8_t_array_offset(buf, self.pos_end, self.utf16_length)

    def __str__(self):
        out = f"String pos start/pos {hex(self.pos_start)}/{hex(self.pos_end)} utf16_length {self.utf16_length} data {self.data} {len(self.data)}"
        return out

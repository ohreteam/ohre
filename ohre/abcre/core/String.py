import io

import leb128

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.misc import Log


class String(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        try:
            self.utf16_length, readed_bytes = leb128.u.decode_reader(io.BytesIO(buf[pos:]))
        except Exception as e:
            Log.error(f"ERROR in String utf16_length decode, e: {e}")
        if (self.utf16_length % 2 == 1):
            self.is_ascii = True
        else:
            self.is_ascii = False # TODO: support non ascii
            Log.error(f"String is_ascii is False! fix it!!! {self.is_ascii}")
        self.utf16_length = self.utf16_length // 2
        self.pos_end += readed_bytes
        self.data, self.pos_end = op._read_uint8_t_array_to_string_offset(buf, self.pos_end, self.utf16_length)

    def __str__(self):
        out = f"s{{[{hex(self.pos_start)}/{hex(self.pos_end)}] "
        if (self.utf16_length != len(self.data)):
            out += "NOT_EQUAL_LEN(DEBUG) "
        out += f"{self.data}}}"
        return out

    def get_str(self):
        return self.data

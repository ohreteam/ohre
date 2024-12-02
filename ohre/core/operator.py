import struct
import ohre.abcre.core.String as String
import leb128
import io


def _read_uint32_t(buf, offset):
    return struct.unpack("I", buf[offset:offset + 4])[0]


def _get_uint32_t_max():
    return 0xffffffff


def _read_uint32_t_offset(buf, offset):
    return struct.unpack("I", buf[offset:offset + 4])[0], offset + 4


def _read_uint8_t(buf, offset):
    return struct.unpack("1B", buf[offset:offset + 1])[0]


def _read_uint8_t_offset(buf, offset):
    return struct.unpack("1B", buf[offset:offset + 1])[0], offset + 1


def _read_uint8_t_array(buf, offset, length):
    return struct.unpack(f"{length}B", buf[offset:offset + length])


def _read_uint8_t_array_offset(buf, offset, length):
    return struct.unpack(f"{length}B", buf[offset:offset + length]), offset + length


def _read_uint8_t_array_to_string_offset(buf, offset, length):
    arr = struct.unpack(f"{length}B", buf[offset:offset + length])
    return _uint8_t_array_to_string(arr), offset + length + 1


def _uint8_t_array_to_string(arr):
    out = ""
    for v in arr:
        out += chr(v)
        if (chr(v) == "\0"):
            break
    return out


def _read_uint16_t_offset(buf, offset):
    return struct.unpack("H", buf[offset:offset + 2])[0], offset + 2


def _read_String_offset(buf, offset):
    s = String.String(buf, offset)
    return s, s.pos_end


def _read_String(buf, offset):
    return String.String(buf, offset)


def _read_uleb128_offset(buf, offset):
    ret, readed_bytes = leb128.u.decode_reader(io.BytesIO(buf[offset:]))
    return ret, offset + readed_bytes


def _read_sleb128_offset(buf, offset):
    ret, readed_bytes = leb128.i.decode_reader(io.BytesIO(buf[offset:]))
    return ret, offset + readed_bytes


def _align4(num):
    if (num % 4 == 0):
        return num
    else:
        return num - num % 4 + 4

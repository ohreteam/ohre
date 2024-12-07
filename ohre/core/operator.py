import io
import struct
from typing import Any, Dict, Iterable, List, Tuple

import leb128

import ohre.abcre.core.String as String
import ohre.misc.const as const


def _read_uint32_t(buf, offset: int) -> int:
    return struct.unpack("I", buf[offset:offset + 4])[0]


def _get_uint32_t_max() -> int:
    return const.UINT32MAX


def _read_uint32_t_offset(buf, offset: int) -> Tuple[int, int]:
    return struct.unpack("I", buf[offset:offset + 4])[0], offset + 4


def _read_uint8_t(buf, offset: int) -> int:
    return struct.unpack("1B", buf[offset:offset + 1])[0]


def _read_uint8_t_offset(buf, offset: int) -> Tuple[int, int]:
    return struct.unpack("1B", buf[offset:offset + 1])[0], offset + 1


def _read_uint8_t_array(buf, offset: int, length: int) -> Tuple[int]:
    return struct.unpack(f"{length}B", buf[offset:offset + length])


def _read_uint8_t_array_offset(buf, offset: int, length: int) -> Tuple[Tuple[int], int]:
    return struct.unpack(f"{length}B", buf[offset:offset + length]), offset + length


def _read_uint8_t_array_to_string_offset(buf, offset: int, length: int) -> Tuple[str, int]:
    arr = struct.unpack(f"{length}B", buf[offset:offset + length])
    return _uint8_t_array_to_string(arr), offset + length + 1


def _uint8_t_array_to_string(arr) -> str:
    out = ""
    for v in arr:
        out += chr(v)
        if (chr(v) == "\0"):
            break
    return out


def _uint8_t_array_to_int(arr: Iterable, len: int = 4) -> int:
    out = 0
    for i in range(len):
        assert arr[i] <= const.UINT8MAX and arr[i] >= 0, "value of uint8_t must be 0 <= v <= UINT8MAX"
        out += (arr[i]) * (2**(8 * i))
    return out


def _read_uint16_t_offset(buf, offset: int) -> Tuple[int, int]:
    return struct.unpack("H", buf[offset:offset + 2])[0], offset + 2


def _read_uintn_offset(buf, offset: int, byte_cnt: int) -> Tuple[int, int]:
    arr, offset = _read_uint8_t_array_offset(buf, offset, byte_cnt)
    ret = _uint8_t_array_to_int(arr, byte_cnt)
    return ret, offset


def _read_float32_t_offset(buf, offset):
    return struct.unpack("1f", buf[offset:offset + 4])[0], offset + 4


def _read_double64_t_offset(buf, offset):
    return struct.unpack("1d", buf[offset:offset + 8])[0], offset + 8


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


if __name__ == "__main__":
    print(hex(_uint8_t_array_to_int((0x34, 0x12, 0, 0))))

import struct


def _read_uint32(buf, offset):
    return struct.unpack("I", buf[offset:offset + 4])[0]


def _read_uint32_t_offset(buf, offset):
    return struct.unpack("I", buf[offset:offset + 4])[0], offset + 4


def _read_uint8_t(buf, offset):
    return struct.unpack("I", buf[offset:offset + 1])[0]


def _read_uint8_t_offset(buf, offset):
    return struct.unpack("I", buf[offset:offset + 1])[0], offset + 1


def _read_TypeDescriptor_offset(buf, offset):
    content = ""
    while offset < len(buf)-1 and chr(buf[offset]) != ';':
        # print(f"buf[offset] {buf[offset]} {chr(buf[offset])} {type(buf[offset])}")
        content += chr(buf[offset])
        offset += 1
    content += chr(buf[offset])
    offset += 1
    return content, offset

def _read_uint8_t_array(buf,offset, length):
    return struct.unpack("s", buf[offset:offset + length])

def _read_uint8_t_array_offset(buf,offset, length):
    return struct.unpack("s", buf[offset:offset + length]), offset + length

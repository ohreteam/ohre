import struct

def _read_uint32(buf, offset):
        return struct.unpack("I", buf[offset:offset + 4])[0]

def _read_uint32_offset(buf, offset):
        return struct.unpack("I", buf[offset:offset + 4])[0], offset+4

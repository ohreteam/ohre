import struct


class Version:
    def __init__(self, version):
        self.version = version

    @property
    def main_ver(self):
        return self.version & 0x0000ff

    @property
    def sub_ver(self):
        return (self.version >> 8) & 0x0000ff

    @property
    def feat_ver(self):
        return (self.version >> 16) & 0x0000ff

    @property
    def build_ver(self):
        return (self.version >> 24) & 0x0000ff

    def __str__(self):
        return f"{self.main_ver}.{self.sub_ver}.{self.feat_ver}.{self.build_ver}"



class AbcHeader:
    def __init__(self,buf):
        self.pos = 0
        self.buf = buf
        self.magic, self.check_sum, self.version, self.file_size, self.foreign_off, self.foreign_size,\
            self.num_classes, self.class_idx_off, self.num_lnps, self.lnp_idx_off, self.num_literal_arrays,\
         self.literal_array_idx_off, self.num_index_regions, self.index_section_off = self._parse_header()

    def _parse_header(self):
        offset = 0
        magic = self._read_string(offset,8)# Magic string. Must be 'P' 'A' 'N' 'D' 'A' '\0' '\0' '\0'
        print(magic, offset)

        offset+=8
        # Adler32
        check_sum = self._read_uint32(offset)
        print(check_sum, offset)

        offset+=4
        # Version of the format. Current version is 0002.
        version_value = self._read_uint32(offset)
        version = Version(version_value)
        print("Version: ",version)
        if not (version.main_ver >= 9 and version.sub_ver >= 0 and version.feat_ver >= 0 and version.build_ver >= 0):
            raise NotImplementedError(
                f"Unsupported ABC Version {version.main_ver}.{version.sub_ver}.{version.feat_ver}.{version.build_ver}")

        offset += 4
        # Size of the file in bytes.
        file_size = self._read_uint32(offset)
        print(file_size)

        # uint32_t
        foreign_off = self._read_uint32(offset + 4)
        print('foreign_off', foreign_off,offset + 4)

        # Size of the foreign region in bytes.
        # uint32_t
        foreign_size = self._read_uint32(offset + 8)
        print('foreign_size', foreign_size,offset + 8)

        # uint32_t
        num_classes = self._read_uint32(offset + 12)
        print('num_classes', num_classes,offset + 12)

        # Offset to the class index structure. The offset must point to a structure in ClassIndex format.
        # uint32_t
        class_idx_off = self._read_uint32(offset + 16)
        print('class_idx_off', class_idx_off,offset + 16)

        # Number of line number programs in the file.
        # Also this is the number of elements in the LineNumberProgramIndex structure.
        # uint32_t
        num_lnps = self._read_uint32(offset + 20)
        print('num_lnps', num_lnps, offset,offset + 20)

        # Offset to the line number program index structure.
        # The offset must point to a structure in LineNumberProgramIndex format.
        # lnp_idx_off
        lnp_idx_off = self._read_uint32(offset + 24)
        print('lnp_idx_off', lnp_idx_off, offset,offset + 24)

        # 	Number of literalArrays defined in the file.
        # 	Also this is the number of elements in the LiteralArrayIndex structure.
        # uint32_t
        num_literal_arrays = self._read_uint32(offset + 28)
        print('num_literal_arrays', num_literal_arrays, offset + 28)

        # Offset to the literalarray index structure.
        # The offset must point to a structure in LiteralArrayIndex format.
        # uint32_t
        literal_array_idx_off = self._read_uint32(offset + 32)
        print('literal_array_idx_off', literal_array_idx_off, offset + 32)

        # Number of the index regions in the file.
        # Also this is the number of elements in the RegionIndex structure.
        # uint32_t
        num_index_regions = self._read_uint32(offset + 36)
        print('num_index_regions', num_index_regions, offset + 36)

        # Offset to the index section.
        # The offset must point to a structure in RegionIndex format.
        # uint32_t
        index_section_off = self._read_uint32(offset + 40)
        print('index_section_off', index_section_off, offset + 40)

        self.pos = offset+44
        print("Final offset is : ",self.pos)
        return [magic, check_sum, version, file_size, foreign_off, foreign_size, num_classes, class_idx_off,
                num_lnps, lnp_idx_off, num_literal_arrays, literal_array_idx_off, num_index_regions,
                index_section_off]

    def _read_string(self, offset, length):
        data = self.buf[offset:offset + length]
        return data.decode('utf-8').replace('\x00', '')

    def _read_uint32(self, offset):
        return struct.unpack('I', self.buf[offset:offset + 4])[0]

    def is_valid(self):
        return self.magic == 'PANDA'


with open('modules.abc','rb') as f:
    buf = f.read()
    header = AbcHeader(buf)
    f.close()
import ohre.core.operator as op


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


class Header:
    def __init__(self, buf):
        self.pos = 0
        self.buf = buf
        self.magic, self.checksum, self.version, self.file_size, self.foreign_off, self.foreign_size, \
            self.num_classes, self.class_idx_off, self.num_lnps, self.lnp_idx_off, self.num_literal_arrays, \
            self.literal_array_idx_off, self.num_index_regions, self.index_section_off = self._parse_header()

    def _parse_header(self):
        offset = 0
        magic = self._read_string(offset, 8)  # Magic string. Must be 'P' 'A' 'N' 'D' 'A' '\0' '\0' '\0'
        print(f"magic {type(magic)} {magic} {offset}")

        offset += 8
        # Adler32
        checksum = op._read_uint32(self.buf, offset)
        print(f"checksum {hex(checksum)} {checksum} {offset}")

        offset += 4
        # Version of the format. Current version is 0002.
        version_value = op._read_uint32(self.buf, offset)
        version = Version(version_value)
        print(f"version {version}")
        if not (version.main_ver >= 9 and version.sub_ver >= 0 and version.feat_ver >= 0 and version.build_ver >= 0):
            raise NotImplementedError(
                f"Unsupported ABC Version {version.main_ver}.{version.sub_ver}.{version.feat_ver}.{version.build_ver}")

        offset += 4
        # Size of the file in bytes.
        file_size = op._read_uint32(self.buf, offset)
        print(f"file_size {hex(file_size)} {file_size}")

        # uint32_t
        foreign_off = op._read_uint32(self.buf, offset + 4)
        print(f"foreign_off {hex(foreign_off)} {foreign_off} {offset + 4}")

        # Size of the foreign region in bytes.
        # uint32_t
        foreign_size = op._read_uint32(self.buf, offset + 8)
        print(f"foreign_size {hex(foreign_size)} {foreign_size} {offset + 8}")

        # uint32_t
        num_classes = op._read_uint32(self.buf, offset + 12)
        print(f"num_classes {hex(num_classes)} {num_classes} {offset + 12}")

        # Offset to the class index structure. The offset must point to a structure in ClassIndex format.
        # uint32_t
        class_idx_off = op._read_uint32(self.buf, offset + 16)
        print(f"class_idx_off {hex(class_idx_off)} {class_idx_off} {offset + 16}")

        # Number of line number programs in the file.
        # Also this is the number of elements in the LineNumberProgramIndex structure.
        # uint32_t
        num_lnps = op._read_uint32(self.buf, offset + 20)
        print(f"num_lnps {hex(num_lnps)} {num_lnps} {offset + 20}")

        # Offset to the line number program index structure.
        # The offset must point to a structure in LineNumberProgramIndex format.
        # lnp_idx_off
        lnp_idx_off = op._read_uint32(self.buf, offset + 24)
        print(f"lnp_idx_off {hex(lnp_idx_off)} {lnp_idx_off} {offset + 24}")

        # 	Number of literalArrays defined in the file.
        # 	Also this is the number of elements in the LiteralArrayIndex structure.
        # uint32_t
        num_literal_arrays = op._read_uint32(self.buf, offset + 28)
        print(f"num_literal_arrays {hex(num_literal_arrays)} {num_literal_arrays} {offset + 28}")

        # Offset to the literalarray index structure.
        # The offset must point to a structure in LiteralArrayIndex format.
        # uint32_t
        literal_array_idx_off = op._read_uint32(self.buf, offset + 32)
        print(f"literal_array_idx_off {hex(literal_array_idx_off)} {literal_array_idx_off} {offset + 32}")

        # Number of the index regions in the file.
        # Also this is the number of elements in the RegionIndex structure.
        # uint32_t
        num_index_regions = op._read_uint32(self.buf, offset + 36)
        print(f"num_index_regions {hex(num_index_regions)} {num_index_regions} {offset + 36}")

        # Offset to the index section.
        # The offset must point to a structure in RegionIndex format.
        # uint32_t
        index_section_off = op._read_uint32(self.buf, offset + 40)
        print(f"index_section_off {hex(index_section_off)} {index_section_off} {offset + 40}")

        self.pos = offset + 44
        print(f"Final offset is : {self.pos}")
        return [magic, checksum, version, file_size, foreign_off, foreign_size, num_classes, class_idx_off,
                num_lnps, lnp_idx_off, num_literal_arrays, literal_array_idx_off, num_index_regions,
                index_section_off]

    def _read_string(self, offset, length):
        data = self.buf[offset:offset + length]
        return data.decode("utf-8").replace("\x00", "")

    def is_valid(self):
        return self.magic == "PANDA"


if __name__ == "__main__":
    with open("modules.abc", "rb") as f:
        buf = f.read()
        header = Header(buf)
        f.close()
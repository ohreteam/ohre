import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion


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


class Header(BaseRegion):
    def __init__(self, buf, pos: int = 0):
        super().__init__(pos)
        self.pos = 0
        self.buf = buf
        self.magic, self.checksum, self.version, self.file_size, self.foreign_off, self.foreign_size, \
            self.num_classes, self.class_region_idx_off, self.num_lnps, self.lnp_idx_off, self.num_literalarrays, \
            self.literalarray_idx_off, self.num_index_regions, self.index_section_off = self._parse_header()

    def _parse_header(self):
        offset = 0
        magic = self._read_string(offset, 8)  # Magic string. Must be 'P' 'A' 'N' 'D' 'A' '\0' '\0' '\0'

        offset += 8
        # Adler32
        checksum = op._read_uint32_t(self.buf, offset)

        offset += 4
        # Version of the format. Current version is 0002.
        version_value = op._read_uint32_t(self.buf, offset)
        version = Version(version_value)
        if not (version.main_ver >= 9 and version.sub_ver >= 0 and version.feat_ver >= 0 and version.build_ver >= 0):
            raise NotImplementedError(
                f"Unsupported ABC Version {version.main_ver}.{version.sub_ver}.{version.feat_ver}.{version.build_ver}")

        offset += 4
        # Size of the file in bytes.
        file_size = op._read_uint32_t(self.buf, offset)

        foreign_off = op._read_uint32_t(self.buf, offset + 4)

        # Size of the foreign region in bytes.
        foreign_size = op._read_uint32_t(self.buf, offset + 8)

        num_classes = op._read_uint32_t(self.buf, offset + 12)

        # Offset to the class index structure. The offset must point to a structure in ClassIndex format.
        class_region_idx_off = op._read_uint32_t(self.buf, offset + 16)

        # Number of line number programs in the file.
        # Also this is the number of elements in the LineNumberProgramIndex structure.
        num_lnps = op._read_uint32_t(self.buf, offset + 20)

        # Offset to the line number program index structure.
        # The offset must point to a structure in LineNumberProgramIndex format.
        lnp_idx_off = op._read_uint32_t(self.buf, offset + 24)

        # 	Number of literalArrays defined in the file.
        # 	Also this is the number of elements in the LiteralArrayIndex structure.
        # reserved from 12.0.6
        num_literalarrays = op._read_uint32_t(self.buf, offset + 28)

        # Offset to the literalarray index structure.
        # The offset must point to a structure in LiteralArrayIndex format.
        # reserved from 12.0.6
        literalarray_idx_off = op._read_uint32_t(self.buf, offset + 32)

        # Number of the index regions in the file.
        # Also this is the number of elements in the IndexSection structure.
        num_index_regions = op._read_uint32_t(self.buf, offset + 36)

        # Offset to the index section.
        # The offset must point to a structure in IndexSection/IndexSection format.
        index_section_off = op._read_uint32_t(self.buf, offset + 40)

        self.pos = offset + 44
        self.pos_end = offset + 44
        return [magic, checksum, version, file_size, foreign_off, foreign_size, num_classes, class_region_idx_off,
                num_lnps, lnp_idx_off, num_literalarrays, literalarray_idx_off, num_index_regions,
                index_section_off]

    def _read_string(self, offset, length):
        data = self.buf[offset:offset + length]
        return data.decode("utf-8").replace("\x00", "")

    def is_valid(self):
        return self.magic == "PANDA"

    def __str__(self):
        out = f"Header: [{hex(self.pos_start)}/{hex(self.pos_end)}] magic {self.magic} \
checksum {hex(self.checksum)} version {self.version} file_size {hex(self.file_size)} \
foreign_off {hex(self.foreign_off)} foreign_size {hex(self.foreign_size)}\n\
num_classes {hex(self.num_classes)} class_region_idx_off {hex(self.class_region_idx_off)} \
num_lnps {hex(self.num_lnps)} lnp_idx_off {hex(self.lnp_idx_off)} \
num_literalarrays {hex(self.num_literalarrays)} literalarray_idx_off {hex(self.literalarray_idx_off)} \
num_index_regions {hex(self.num_index_regions)} index_section_off {hex(self.index_section_off)}"
        return out


if __name__ == "__main__":
    with open("modules.abc", "rb") as f:
        buf = f.read()
        header = Header(buf)
        f.close()

from ohre.res_analyzer.oh_resbuf import ResIndexBuf
import struct

def generate_valid_buffer():
    version = b'TestVersion'+b'\x00' * (128-len(b'TestVersion'))  # 填充到128字节
    file_size = struct.pack('<II', 0, 0)
    total_str = version + file_size
    return total_str


def generate_invalid_buffer():
    header_str = b'TestVersion' + b'\x00' * (136-len(b'TestVersion'))
    return header_str

class TestResIndexBuf:
    def test_read_header_valid(self):
        buf = generate_valid_buffer()
        res_index_buf = ResIndexBuf(buf)
        header = res_index_buf.header
        assert header['version']=='TestVersion'
        assert header['file_size']==0
        assert header['limit_key_config_count']==0

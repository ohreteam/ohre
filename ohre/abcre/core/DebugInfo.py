from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.String import String
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.misc import Log


class DebugInfo(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        # line_start==4294967295 means invalid line start
        self.buf = buf  # TODO: delete it in future, for debug now
        self.line_start, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)

        self.num_parameters, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        self.parameters, self.pos_end = op._read_uleb128_array_offset(buf, self.pos_end, self.num_parameters)
        assert len(self.parameters) == self.num_parameters
        self.constant_pool_size, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        self.constant_pool, self.pos_end = op._read_uleb128_array_offset(buf, self.pos_end, self.constant_pool_size)
        assert len(self.constant_pool) == self.constant_pool_size
        self.line_number_program_idx, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)

    def __str__(self):
        out_parameters = ""
        for param in self.parameters:
            if (param != 0):
                s = String(self.buf, param)
                out_parameters += f"{s.get_str()};"
            else:
                out_parameters += " ;"

        out_constant_pool = ""
        for cp in self.constant_pool:
            out_constant_pool += f"{hex(cp)} "

        out_debuginfo_data = f"DebugInfo: [{hex(self.pos_start)}/{hex(self.pos_end)}] \
line_start {hex(self.line_start)} \
num_parameters {hex(self.num_parameters)} parameters({len(self.parameters)}): {out_parameters} \
constant_pool_size {hex(self.constant_pool_size)} constant_pool({len(self.constant_pool)}): {out_constant_pool} \
line_number_program_idx {hex(self.line_number_program_idx)}"
        return out_debuginfo_data

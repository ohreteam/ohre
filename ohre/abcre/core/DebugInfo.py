from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.Field import Field
from ohre.abcre.core.Method import Method
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.abcre.enum.ClassTag import ClassTag
from ohre.abcre.enum.SourceLanguage import SourceLanguage
from ohre.misc import Log


class DebugInfo(BaseRegion):
    def __init__(self, buf, debug_offsets: tuple):
        self.debug_tuple = debug_offsets
        self.debug_offset = op._uint8_t_array_to_int(self.debug_tuple)

        # line_start	uleb128
        # line_start==4294967295 means invalid line start
        self.line_start, self.pos_end = op._read_uleb128_offset(buf, self.debug_offset)
        # num_parameters	uleb128
        self.num_parameters, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        # parameters	uleb128[]
        self.parameters, self.pos_end = _read_parameters_array(buf, self.num_parameters, self.pos_end)
        # constant_pool_size	uleb128
        self.constant_pool_size, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        # constant_pool	uleb128[]
        self.constant_pool, self.pos_end = _read_constant_pool(buf, self.constant_pool_size, self.pos_end)
        # line_number_program_idx	uleb128
        self.line_number_program_idx, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)

    def __str__(self):
        parameters_output = []
        for i, param in enumerate(self.parameters):
            parameters_output.append(f"{i}-th {hex(param)}, {param}")
        parameters_output = ";".join(parameters_output)

        constant_pool_output = []
        for i, cp in enumerate(self.constant_pool):
            constant_pool_output.append(f"{i}-th {hex(cp)}, {cp}")
        constant_pool_output = ";".join(constant_pool_output)

        out_debuginfo_data = f"Debug Start Offfset: {hex(self.debug_offset)},{self.debug_offset} line_start: {hex(self.line_start)}, {self.line_start} \
num_parameters: {hex(self.num_parameters)} parameters: {parameters_output} constant_pool_size: {hex(self.constant_pool_size)},{self.constant_pool_size} \
constant_pool: {constant_pool_output} line_number_program_idx: {hex(self.line_number_program_idx)}, {self.line_number_program_idx} pos_end: {hex(self.pos_end)},{self.pos_end}"
        return out_debuginfo_data


def _read_constant_pool(buf, constant_pool_size, pos_end):
    constant_pool_size_array = []
    for _ in range(constant_pool_size):
        cps_offsets, pos_end = op._read_uleb128_offset(buf, pos_end)
        constant_pool_size_array.append(cps_offsets)
    return constant_pool_size_array, pos_end


def _read_parameters_array(buf, num_parameters, pos_end):
    parameters_array = []
    for _ in range(num_parameters):
        param_offset, pos_end = op._read_uleb128_offset(buf, pos_end)
        if param_offset == 0:
            parameters_array.append("")
        else:
            param_string, _ = op._read_String_offset(buf, param_offset)
            parameters_array.append(param_string.data)
    return parameters_array, pos_end

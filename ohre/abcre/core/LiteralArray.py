from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.enum.LiteralTag import LiteralTag
from ohre.abcre.core.Literal import Literal
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.misc import Log


class LiteralArray(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        self.buf = buf  # TODO: delete it in the future! now it just for debug print
        # num of literals that a literalarray has
        self.num_literals, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.literals: list[Literal] = list()
        i = 0
        while (i < self.num_literals):
            # coressponding to LiteralDataAccessor::EnumerateLiteralVals in libpandafile\literal_data_accessor-inl.h
            tag, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
            value = 0
            if (tag == LiteralTag.INTEGER or tag == LiteralTag.LITERALBUFFERINDEX):
                value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.INTEGER_8):  # TODO: not sure, check it in the future
                value, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
                print(f"{hex(self.pos_end)} LiteralTag DEBUG tag={hex(tag)} INTEGER_8 HIT")
            elif (tag == LiteralTag.DOUBLE):
                value, self.pos_end = op._read_double64_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.BOOL):
                value, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
                value = bool(value)
            elif (tag == LiteralTag.FLOAT):
                value, self.pos_end = op._read_float32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.STRING or tag == LiteralTag.METHOD
                  or tag == LiteralTag.GETTER or tag == LiteralTag.SETTER
                  or tag == LiteralTag.GENERATORMETHOD or tag == LiteralTag.LITERALARRAY
                  or tag == LiteralTag.ASYNCGENERATORMETHOD):
                value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.METHODAFFILIATE):
                value, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.BUILTINTYPEINDEX or tag == LiteralTag.ACCESSOR
                  or tag == LiteralTag.NULLVALUE):
                value, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.ARRAY_U1 or tag == LiteralTag.ARRAY_U8
                  or tag == LiteralTag.ARRAY_I8 or tag == LiteralTag.ARRAY_U16
                  or tag == LiteralTag.ARRAY_I16 or tag == LiteralTag.ARRAY_U32
                  or tag == LiteralTag.ARRAY_I32 or tag == LiteralTag.ARRAY_U64
                  or tag == LiteralTag.ARRAY_I64 or tag == LiteralTag.ARRAY_F32
                  or tag == LiteralTag.ARRAY_F64 or tag == LiteralTag.ARRAY_STRING):
                print(f"LiteralTag DEBUG tag end at {hex(self.pos_end)}")
                value, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
                print(f"{hex(self.pos_end)} {hex(tag)} {LiteralTag.get_code_name(tag)} \
pos_end {hex(self.pos_end)} value {value}")
                i = self.num_literals
            elif (tag == LiteralTag.UNKOWN_6B):
                print(f"{hex(self.pos_end)} LiteralTag DEBUG tag={hex(tag)} UNKOWN_6B HIT")
                value, self.pos_end = op._read_uintn_offset(buf, self.pos_end, 6)
            else:
                print(f"{hex(self.pos_end)} LiteralTag DEBUG tag={hex(tag)} NOT valid!")
            lit = Literal(tag, value)
            i += 2
            self.literals.append(lit)

    def __str__(self):
        literals_out = ""
        if (self.num_literals // 2 != len(self.literals)):
            literals_out += "LEN-NOT-VALID! "
        for lit in self.literals:
            literals_out += lit.get_str(self.buf) + ", "
        out = f"LiteralArray: [{hex(self.pos_start)}/{hex(self.pos_end)}] num_literals {hex(self.num_literals)} \
literals({hex(len(self.literals))}) {literals_out}"
        return out

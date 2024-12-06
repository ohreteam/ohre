from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.enum.LiteralTag import LiteralTag
from ohre.abcre.core.Literal import Literal
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.misc import Log


class LiteralArray(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        # num of literals that a literalarray has
        self.num_literals, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        print(f"self.num_literals {self.num_literals} self.pos_end {hex(self.pos_end)}")
        self.literals: list[Literal] = list()
        i = 0
        while (i < self.num_literals):
            tag, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
            print(f"tag {tag} {LiteralTag.get_code_name(tag)}", end=" : ")
            value = None
            if (tag == LiteralTag.INTEGER or LiteralTag.LITERALBUFFERINDEX):
                value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.DOUBLE):
                pass
                # value, self.pos_end = op._read_double64_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.BOOL):
                value, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
                value = bool(value)
            elif (tag == LiteralTag.FLOAT):
                pass
                # value, self.pos_end = op._read_float32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.STRING or LiteralTag.METHOD
                  or tag == LiteralTag.GETTER or LiteralTag.SETTER
                  or tag == LiteralTag.GENERATORMETHOD or LiteralTag.LITERALARRAY
                  or LiteralTag.ASYNCGENERATORMETHOD):
                value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.METHODAFFILIATE):
                value, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.BUILTINTYPEINDEX or LiteralTag.ACCESSOR
                  or tag == LiteralTag.NULLVALUE):
                value, self.pos_end = op._read_uint8_t_offset(buf, self.pos_end)
            elif (tag == LiteralTag.ARRAY_U1 or LiteralTag.ARRAY_U8
                  or tag == LiteralTag.ARRAY_I8 or tag == LiteralTag.ARRAY_U16
                  or tag == LiteralTag.ARRAY_I16 or tag == LiteralTag.ARRAY_U32
                  or tag == LiteralTag.ARRAY_I32 or tag == LiteralTag.ARRAY_U64
                  or tag == LiteralTag.ARRAY_I64 or tag == LiteralTag.ARRAY_F32
                  or tag == LiteralTag.ARRAY_F64 or tag == LiteralTag.ARRAY_STRING):
                value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
                i = self.num_literals
            else:
                Log.critical(f"LiteralTag tag={tag} NOT valid!")

            i += 2
            print(f"value: {hex(value)} i={i} num_literals {self.num_literals}")

        # self.literals, self.pos_end = "", self.pos_end  # op._read_literal(buf, self.pos_end)

    def __str__(self):
        out = f"LiteralArray: [{hex(self.pos_start)}/{hex(self.pos_end)}] \
num_literals {hex(self.num_literals)} literals {self.literals}"
        return out

from typing import Any, Dict, Iterable, List, Tuple

import ohre.abcre.core.String as String
import ohre.core.ohoperator as op
import ohre.misc.const as const
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.enum.LiteralTag import LiteralTag


class Literal():
    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def IsBoolValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_U1 or self.tag == LiteralTag.BOOL):
            return True
        return False

    def IsByteValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_U8 or self.tag == LiteralTag.ARRAY_I8
           or self.tag == LiteralTag.TAGVALUE or self.tag == LiteralTag.ACCESSOR
           or self.tag == LiteralTag.NULLVALUE):
            return True
        return False

    def IsShortValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_U16 or self.tag == LiteralTag.ARRAY_I16):
            return True
        return False

    def IsIntegerValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_U32 or self.tag == LiteralTag.ARRAY_I32
                or self.tag == LiteralTag.INTEGER):
            return True
        return False

    def IsLongValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_U64 or self.tag == LiteralTag.ARRAY_I64):
            return True
        return False

    def IsFloatValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_F32 or self.tag == LiteralTag.FLOAT):
            return True
        return False

    def IsDoubleValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_F64 or self.tag == LiteralTag.DOUBLE):
            return True
        return False

    def IsStringValue(self) -> bool:
        if (self.tag == LiteralTag.ARRAY_STRING or self.tag == LiteralTag.STRING
            or self.tag == LiteralTag.METHOD or self.tag == LiteralTag.GETTER
            or self.tag == LiteralTag.SETTER or self.tag == LiteralTag.GENERATORMETHOD
                or self.tag == LiteralTag.ASYNCGENERATORMETHOD):
            return True
        return False

    def __str__(self):
        out = f"{LiteralTag.get_code_name(self.tag)} "
        if (self.IsBoolValue()):
            if (self.value):
                out += f"{self.value}"
            else:
                out += f"{self.value}"
        elif (self.IsByteValue()):
            out += f"{hex(self.value)}"
        elif (self.IsShortValue()):
            out += f"{hex(self.value)}"
        elif (self.IsIntegerValue()):
            if (self.value > const.UINT32MAX):
                out += f"value NOT valid "
            out += f"{hex(self.value)}"
        elif (self.IsLongValue()):
            out += f"{hex(self.value)}"
        elif (self.IsFloatValue()):
            out += f"{self.value}"
        elif (self.IsDoubleValue()):
            out += f"{self.value}"
        elif (self.IsStringValue()):
            out += f"{hex(self.value)}"
        else:
            out += f"Literal-IS-UNKNOWN {hex(self.value)}"
        return out

    def get_str(self, buf=None):
        out = f"{LiteralTag.get_code_name(self.tag)} "
        if (self.IsBoolValue()):
            if (self.value):
                out += f"True"
            else:
                out += f"False"
        elif (self.IsByteValue()):
            out += f"{hex(self.value)}"
        elif (self.IsShortValue()):
            out += f"{hex(self.value)}"
        elif (self.IsIntegerValue()):
            if (self.value > const.UINT32MAX):
                out += f"NOT valid "
            out += f"{hex(self.value)}"
        elif (self.IsLongValue()):
            out += f"{hex(self.value)}"
        elif (self.IsFloatValue()):
            out += f"{self.value}"
        elif (self.IsDoubleValue()):
            out += f"{self.value}"
        elif (self.tag == LiteralTag.STRING and buf is not None):
            s = String.String(buf, self.value)
            out += f"{s}"
        elif (self.IsStringValue() and self.tag != LiteralTag.STRING):
            out += f"{hex(self.value)}"
        else:
            out += f"Literal-IS-UNKNOWN {hex(self.value)}"
        return out

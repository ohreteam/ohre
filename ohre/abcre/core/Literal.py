from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.enum.LiteralTag import LiteralTag
from ohre.abcre.core.BaseRegion import BaseRegion


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

    def IsFloatValue(self) -> bool:
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

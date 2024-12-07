from ohre.abcre.enum.BaseEnum import BaseEnum


class LiteralTag(BaseEnum):
    def __init__(self):
        super().__init__()
    TAGVALUE = 0x00
    BOOL = 0x01
    INTEGER_8 = TAGVALUE
    INTEGER = 0x02
    FLOAT = 0x03
    DOUBLE = 0x04
    STRING = 0x05
    METHOD = 0x06
    GENERATORMETHOD = 0x07
    ACCESSOR = 0x08
    METHODAFFILIATE = 0x09
    ARRAY_U1 = 0x0a
    ARRAY_U8 = 0x0b
    ARRAY_I8 = 0x0c
    ARRAY_U16 = 0x0d
    ARRAY_I16 = 0x0e
    ARRAY_U32 = 0x0f
    ARRAY_I32 = 0x10
    ARRAY_U64 = 0x11
    ARRAY_I64 = 0x12
    ARRAY_F32 = 0x13
    ARRAY_F64 = 0x14
    ARRAY_STRING = 0x15
    ASYNCGENERATORMETHOD = 0x16
    LITERALBUFFERINDEX = 0x17
    LITERALARRAY = 0x18
    BUILTINTYPEINDEX = 0x19
    GETTER = 0x1a
    SETTER = 0x1b
    UNKOWN_6B = 0x2e
    NULLVALUE = 0xff

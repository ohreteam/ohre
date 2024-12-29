from ohre.abcre.enum.BaseEnum import BaseEnum


class AsmTypes(BaseEnum):
    uint_types = {"u8", "u16", "u32", "u64"}
    ACC = "acc"
    VAR = "v"  # e.g. v0, v1, v2
    ARG = "a"  # e.g. a0, a1, a2
    REG = "reg"  # register
    IMM = "imm"  # AsmArg: value is the actual value of immediate number
    NULL = "null"  # AsmArg: value not valid
    TRUE = "true"  # AsmArg: value not valid
    FALSE = "false"  # AsmArg: value not valid
    ZERO = "zero"  # AsmArg: value not valid
    LABEL = "label"  # AsmArg: value not valid
    STR = "str"
    MODULE = "module"
    UNDEFINED = "undefined"
    UNKNOWN = "unknown"  # default value in this proj

    def __init__(self):
        super().__init__()

    @classmethod
    def is_uint(cls, type_name: str):
        if (type_name in cls.uint_types):
            return True
        return False

from ohre.abcre.enum.BaseEnum import BaseEnum


class AsmTypes(BaseEnum):
    uint_types = {"u1", "u8", "u16", "u32", "u64"}
    int_types = {"i1", "i8", "i16", "i32", "i64"}
    float_types = {"f32", "f64"}
    str_types = {"string"}
    ACC = "acc"
    VAR = "v"  # e.g. v0, v1, v2
    ARG = "a"  # e.g. a0, a1, a2
    IMM = "imm"  # AsmArg: value is the actual value of immediate number
    NULL = "null"  # AsmArg: value not valid
    INF = "inf"  # infinity
    NAN = "nan"  # not a num
    TRUE = "true"  # AsmArg: value not valid
    FALSE = "false"  # AsmArg: value not valid
    ZERO = "zero"  # AsmArg: value not valid
    LABEL = "label"  # AsmArg: value not valid
    STR = "str"
    MODULE = "module"
    METHOD = "method"
    METHOD_OBJ = "method_obj"  # TODO: merge it with method?
    FIELD = "field"  # TODO: support assign inst with field
    OBJECT = "object"
    ARRAY = "array"  # value is also arg
    UNDEFINED = "undefined"
    HOLE = "hole"
    LEXENV = "lexenv"
    UNKNOWN = "unknown"  # default value in this proj # maybe same as Any

    def __init__(self):
        super().__init__()

    def is_var_like(self):
        pass

    @classmethod
    def is_uint(cls, type_name: str):
        if (type_name in cls.uint_types):
            return True
        return False

    @classmethod
    def is_int(cls, type_name: str):
        if (type_name in cls.int_types):
            return True
        if (type_name in cls.uint_types):
            return True
        return False

    @classmethod
    def is_float(cls, type_name: str):
        if (type_name in cls.float_types):
            return True
        return False

    @classmethod
    def is_str(cls, type_name: str):
        if (type_name in cls.str_types):
            return True
        return False

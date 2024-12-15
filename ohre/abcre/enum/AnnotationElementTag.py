from ohre.abcre.enum.BaseEnum import BaseEnum


class AnnotationElementTag(BaseEnum):
    def __init__(self):
        super().__init__()
    map = {"u1": "1",
           "i8": "2",
           "u8": "3",
           "i16": "4",
           "u16": "5",
           "i32": "6",
           "u32": "7",
           "i64": "8",
           "u64": "9",
           "f32": "A",
           "f64": "B",
           "string": "C",
           "method": "E",
           "annotation": "G",
           "literalarray": "#",
           "unknown": "0"}
    u1 = "1"
    i8 = "2"
    u8 = "3"
    i16 = "4"
    u16 = "5"
    i32 = "6"
    u32 = "7"
    i64 = "8"
    u64 = "9"
    f32 = "A"
    f64 = "B"
    string = "C"
    method = "E"
    annotation = "G"
    literalarray = "#"
    unknown = "0"

    @classmethod
    def get_type_str(cls, num: int):
        for k, v in cls.map.items():
            if (ord(v) == num):
                return k
        return "UNKNOWN"

    @classmethod
    def get_type_int(cls, value: str):
        for k, v in cls.map.items():
            if (k == value):
                return ord(v)
        return 0

    @classmethod
    def is_longer_than_32bit(cls, num: int):
        smaller_than_32bit_set = {"u1", "i8", "u8", "i16", "u16", "i32", "u32", "f32"}
        for k, v in cls.map.items():
            if (ord(v) == num and k in smaller_than_32bit_set):
                return False
        return True

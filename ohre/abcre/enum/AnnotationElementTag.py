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
    def get_type_str(cls, value: int):
        for k, v in cls.map.items():
            if (ord(v) == value):
                return k
        return "UNKNOWN"

    @classmethod
    def get_type_int(cls, value: str):
        for k, v in cls.map.items():
            if (k == value):
                return ord(v)
        return 0

from ohre.abcre.enum.BaseEnum import BaseEnum


class AsmTpye(BaseEnum):
    uint_types = {"u8", "u16", "u32", "u64"}

    def __init__(self):
        super().__init__()

    @classmethod
    def is_uint(cls, type_name: str):
        if (type_name in cls.uint_types):
            return True
        return False

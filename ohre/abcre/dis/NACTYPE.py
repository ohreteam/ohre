from ohre.abcre.enum.BaseEnum import BaseEnum


class NACTYPE(BaseEnum):
    def __init__(self):
        super().__init__()
    ASSIGN = 0  # at most 3 arg
    COND_JMP = 1  # 3 arg
    UNCN_JMP = 2  # 1 arg # unconditional
    CALL = 3  # 1 or more arg
    COND_THROW = 4  # 3 arg
    UNCN_THROW = 5  # 1 arg
    RETURN = 6  # 1 arg
    IMPORT = 11
    LABEL = 12
    UNKNOWN = 99

    @classmethod
    def get_NAC_type(cls, op: str) -> int:
        return NACTYPE.UNKNOWN
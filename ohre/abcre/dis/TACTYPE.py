
from ohre.abcre.enum.BaseEnum import BaseEnum


class TACTYPE(BaseEnum):
    def __init__(self):
        super().__init__()
    ASSIGN = 0
    ASSIGN_BI = 1
    COND_JMP = 10  # 3 arg
    UNCN_JMP = 11  # 1 arg # unconditional
    RETURN = 20
    UNKNOWN = 99

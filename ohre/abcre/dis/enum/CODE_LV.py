from ohre.abcre.enum.BaseEnum import BaseEnum


class CODE_LV(BaseEnum):
    def __init__(self):
        super().__init__()
    NATIVE = 0
    NATIVE_BLOCK_SPLITED = 1
    TAC = 2
    IR_LV2 = 3

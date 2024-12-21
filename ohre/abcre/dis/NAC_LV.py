from ohre.abcre.enum.BaseEnum import BaseEnum


class NAC_LV(BaseEnum):
    def __init__(self):
        super().__init__()
    NATIVE = 0
    NATIVE_BLOCK_SPLITED = 1
    IR_LV1 = 2
    IR_LV2 = 3

from ohre.abcre.enum.BaseEnum import BaseEnum


class FunctionKind(BaseEnum):
    def __init__(self):
        super().__init__()
    NOTDEFINE = 0x0
    FUNCTION = 0x1
    NC_FUNCTION = 0x2
    GENERATOR_FUNCTION = 0x3
    ASYNC_FUNCTION = 0x4
    ASYNC_GENERATOR_FUNCTION = 0x5
    ASYNC_NC_FUNCTION = 0x6
    CONCURRENT_FUNCTION = 0x7

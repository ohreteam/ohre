from ohre.abcre.enum.BaseEnum import BaseEnum


class MethodTag(BaseEnum):
    def __init__(self):
        super().__init__()
    NOTHING = 0x00
    CODE = 0x01
    SOURCE_LANG = 0x02
    RUNTIME_ANNOTATION = 0x03
    RUNTIME_PARAM_ANNOTATION = 0x04
    DEBUG_INFO = 0x05
    ANNOTATION = 0x06
    PARAM_ANNOTATION = 0x07
    TYPE_ANNOTATION = 0x08
    RUNTIME_TYPE_ANNOTATION = 0x09

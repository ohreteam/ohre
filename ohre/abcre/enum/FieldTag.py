from ohre.abcre.enum.BaseEnum import BaseEnum


class FieldTag(BaseEnum):
    def __init__(self):
        super().__init__()
    NOTHING = 0x00
    INT_VALUE = 0x01
    VALUE = 0x02
    RUNTIME_ANNOTATIONS = 0x03
    ANNOTATIONS = 0x04
    RUNTIME_TYPE_ANNOTATION = 0x05
    TYPE_ANNOTATION = 0x06

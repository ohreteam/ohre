from ohre.abcre.enum.BaseEnum import BaseEnum


class ClassTag(BaseEnum):
    def __init__(self):
        super().__init__()
    NOTHING = 0x00
    INTERFACES = 0x01
    SOURCE_LANG = 0x02
    RUNTIME_ANNOTATION = 0x03
    ANNOTATION = 0x04
    RUNTIME_TYPE_ANNOTATION = 0x05
    TYPE_ANNOTATION = 0x06
    SOURCE_FILE = 0x07

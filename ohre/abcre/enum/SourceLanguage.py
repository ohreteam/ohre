from ohre.abcre.enum.BaseEnum import BaseEnum


class SourceLanguage(BaseEnum):
    def __init__(self):
        super().__init__()
    Reserved = 0x00
    PandaAssembly = 0x01
    Reserved02 = 0x02  # - 0x0f
    Reserved03 = 0x03
    Reserved04 = 0x04
    Reserved05 = 0x05
    Reserved06 = 0x06
    Reserved07 = 0x07
    Reserved08 = 0x08
    Reserved09 = 0x09
    Reserved0a = 0x0a
    Reserved0b = 0x0b
    Reserved0c = 0x0c
    Reserved0d = 0x0d
    Reserved0e = 0x0e
    Reserved0f = 0x0f

from ohre.abcre.enum.BaseEnum import BaseEnum


class SourceLanguage(BaseEnum):
    def __init__(self):
        super().__init__()
    Reserved = 0x00
    PandaAssembly = 0x01
    # Reserved 0x02 - 0x0f

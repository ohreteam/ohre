from ohre.abcre.enum.BaseEnum import BaseEnum


class FieldAccessFlags(BaseEnum):
    def __init__(self):
        super().__init__()
    ACC_PUBLIC = 0x0001  # Declared public; may be accessed from outside its package.
    ACC_PRIVATE = 0x0002  # Declared private; usable only within the defining class.
    ACC_PROTECTED = 0x0004  # Declared protected; may be accessed within subclasses.
    ACC_STATIC = 0x0008  # Declared static.
    ACC_FINAL = 0x0010  # Declared final; never directly assigned to after object construction (JLS §17.5).
    ACC_VOLATILE = 0x0040  # Declared volatile; cannot be cached.
    ACC_TRANSIENT = 0x0080  # Declared transient; not written or read by a persistent object manager.
    ACC_SYNTHETIC = 0x1000  # Declared synthetic; not present in the source code.
    ACC_ENUM = 0x4000  # Declared as an element of an enum.


from ohre.misc.utils import is_uppercase_or_underscore


class BaseEnum():
    def __init__(self):
        pass

    @classmethod
    def get_code_name(cls, value) -> str:
        for name, val in cls.__dict__.items():
            if (val == value and is_uppercase_or_underscore(name)):
                return name
        return value

    @classmethod
    def get_bitmap_name(cls, value) -> str:
        flag_name_l = list()
        for name, val in cls.__dict__.items():
            if (isinstance(val, int) and (value & val) and is_uppercase_or_underscore(name)):
                flag_name_l.append(name.strip())
                value -= val
        outstr = ""
        if (value != 0):
            outstr = f"{hex(value)}|"
        flag_name_l.reverse()
        for i in range(len(flag_name_l)):
            if (i != 0):
                outstr += f"|{flag_name_l[i]}"
            else:
                outstr += f"{flag_name_l[i]}"
        if (outstr == ""):
            outstr = "0"
        return outstr

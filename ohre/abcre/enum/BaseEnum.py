
from ohre.misc.utils import is_uppercase_or_underscore


class BaseEnum():
    def __init__(self):
        pass

    @classmethod
    def get_code_name(cls, value) -> str:
        for name, val in cls.__dict__.items():
            if val == value and is_uppercase_or_underscore(name):
                return name
        return ""

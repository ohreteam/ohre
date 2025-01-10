from ohre.abcre.enum.BaseEnum import BaseEnum


class TACTYPE(BaseEnum):
    def __init__(self):
        super().__init__()
    ASSIGN = 0
    IMPORT = 9  # acc = module(xxx)
    COND_JMP = 10  # 3 arg # if(x op y) jmp ABC
    UNCN_JMP = 11  # 1 arg # unconditional jmp ABC
    COND_THR = 12  # 3 arg # conditional throw # # if(x op y) throw exception
    UNCN_THR = 13  # 1 arg: exception that would be throw # unconditional throw
    RETURN = 20  # 1 arg: value be returned # return acc/undef...
    CALL = 21  # at least 2 args: acc, arg_len
    LABEL = 22  # 1 arg: label's name
    UNKNOWN = 99

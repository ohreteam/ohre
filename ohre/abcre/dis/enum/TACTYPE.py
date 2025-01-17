from ohre.abcre.enum.BaseEnum import BaseEnum


class TACTYPE(BaseEnum):
    def __init__(self):
        super().__init__()
    ASSIGN = 0  # a = b; a = b rop c; a = rop b; # def var: arg[0]
    IMPORT = 9  # acc = module(xxx) # def var: arg[0]
    COND_JMP = 10  # 3 arg # if(x op y) jmp ABC # no def var
    UNCN_JMP = 11  # 1 arg # unconditional jmp ABC # no def var
    COND_THR = 12  # 3 arg # conditional throw # # if(x op y) throw exception # no def var
    UNCN_THR = 13  # 1 arg: exception that would be throw # unconditional throw # no def var
    RETURN = 20  # 1 arg: value be returned # return acc/undef... # no def var
    CALL = 21  # at least 2 args: acc, arg_len # def var: arg[0]
    LABEL = 22  # 1 arg: label's name # no def var
    UNKNOWN = 99
    
# NOTE: if a tac inst will def a arg, that def arg must be def-ed after all other args used
# if a tac inst has define something, then it must store to arg[0], and all other args is read-only(means used)
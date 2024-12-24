from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.TACTYPE import TACTYPE


class TAC():  # Three Address Code
    def __init__(self, optype=TACTYPE.UNKNOWN, args: List[AsmArg] = None, rop="", log=""):
        self.optype = optype
        self.args = args
        self.rop = rop  # rhs op # e.g. acc = a1 + v1 # rop is "+"
        self.log = log

    @classmethod
    def tac_assign(cls, dst: AsmArg, src0: AsmArg, src1: AsmArg = None, rop="", log: str = ""):
        if (src1 is None):
            return TAC(TACTYPE.ASSIGN, [dst, src0], log=log)
        assert src1 is not None and rop is not None and len(rop) > 0
        return TAC(TACTYPE.ASSIGN_BI, [dst, src0, src1], rop=rop, log=log)

    @classmethod
    def tac_cond_jmp(cls, dst: AsmArg, para0: AsmArg, para1: AsmArg, rop, log: str = ""):
        return TAC(TACTYPE.COND_JMP, [dst, para0, para1], rop=rop, log=log)

    @classmethod
    def tac_uncn_jmp(cls, dst: AsmArg, log: str = ""):
        return TAC(TACTYPE.UNCN_JMP, [dst], log=log)

    @classmethod  # TODO: for debug, store some nac and just display it for debug
    def tac_return(cls, paras: List[AsmArg] = None, log: str = ""):
        return TAC(TACTYPE.UNKNOWN, paras, log=log)

    @classmethod  # TODO: for debug, store some nac and just display it for debug
    def tac_unknown(cls, paras: List[AsmArg] = None, log: str = ""):
        return TAC(TACTYPE.UNKNOWN, paras, log=log)

    def __str__(self):
        return self.debug_short()

    def debug_short(self):
        out = f"[{TACTYPE.get_code_name(self.optype)}]\t"

        for i in range(len(self.args)):
            out += f"{self.args[i].debug_short()}, "
        return out

    def debug_deep(self):
        out = f"[{TACTYPE.get_code_name(self.optype)}]\t"
        for i in range(len(self.args)):
            out += f"{self.args[i].debug_deep()} "
            if (i == 1 and self.rop is not None and len(self.rop) > 0):
                out += f"({self.rop}) "
        if (self.log is not None and len(self.log) > 0):
            out += f" // {self.log}"
        return out

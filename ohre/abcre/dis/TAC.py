from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.TACTYPE import TACTYPE
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.AsmTypes import AsmTypes


class TAC(DebugBase):  # Three Address Code
    def __init__(self, optype=TACTYPE.UNKNOWN, args: List[AsmArg] = None, rop="", log: str = "", this: AsmArg = None):
        self.optype = optype
        # === CALL: if optype == TACTYPE.CALL
        # args[0]: acc(called method) # args[1]: arg len # args[2]: arg0 # args[3] arg1 ...
        # this[opt]: this pointer
        self.args = args
        # rhs op # e.g. acc = a1 + v1 (rop is `+`) acc = -acc (rop is `-`) #  # TODO: maybe a roptype class?
        self.rop = rop
        self.log: str = log
        self.this: str = this  # this pointer, maybe point to a object/module

    @classmethod
    def tac_assign(cls, dst: AsmArg, src0: AsmArg, src1: AsmArg = None, rop="", log: str = ""):
        if (src1 is None and len(rop) == 0):
            return TAC(TACTYPE.ASSIGN, [dst, src0], log=log)
        if (src1 is None and len(rop) > 0):  # e.g. acc = -acc
            return TAC(TACTYPE.ASSIGN, [dst, src0], rop=rop, log=log)
        assert src1 is not None and rop is not None and len(rop) > 0
        print(f"ASSIGN(with 2 src): dst {dst} src0 {src0} src1 {src1} rop {rop}")
        return TAC(TACTYPE.ASSIGN, [dst, src0, src1], rop=rop, log=log)

    @classmethod
    def tac_cond_jmp(cls, dst: AsmArg, para0: AsmArg, para1: AsmArg, rop, log: str = ""):
        return TAC(TACTYPE.COND_JMP, [dst, para0, para1], rop=rop, log=log)

    @classmethod
    def tac_uncn_jmp(cls, dst: AsmArg, log: str = ""):
        return TAC(TACTYPE.UNCN_JMP, [dst], log=log)

    @classmethod
    def tac_import(cls, module_name: AsmArg, log: str = ""):
        return TAC(TACTYPE.IMPORT, [AsmArg(AsmTypes.ACC), module_name], log=log)

    @classmethod
    def tac_return(cls, val: AsmArg, log: str = ""):
        return TAC(TACTYPE.RETURN, [val], log=log)

    @classmethod
    def tac_call(cls, arg_len: AsmArg = None, paras: List[AsmArg] = None, this: AsmArg = None, log: str = ""):
        return TAC(TACTYPE.CALL, [AsmArg(AsmTypes.ACC), arg_len, *paras], this=this, log=log)

    @classmethod
    def tac_label(cls, label: AsmArg, log: str = ""):
        return TAC(TACTYPE.LABEL, [label], log=log)

    @classmethod  # TODO: for debug, store some nac and just display it for debug
    def tac_unknown(cls, paras: List[AsmArg] = None, log: str = ""):
        return TAC(TACTYPE.UNKNOWN, paras, log=log)

    def _debug_str(self):
        out = f"[{TACTYPE.get_code_name(self.optype)}]\t"
        for i in range(len(self.args)):
            out += f"{self.args[i]._debug_str()}, "
        return out

    def _args_and_rop_common_debug_str(self):
        out = f""
        for i in range(len(self.args)):
            out += f"{self.args[i]._debug_vstr()} "
            if (i == 1 and self.rop is not None and len(self.rop) > 0):
                out += f"({self.rop}) "
        return out

    def _debug_vstr(self):
        out = f"[{TACTYPE.get_code_name(self.optype)}]\t"
        if (self.optype == TACTYPE.ASSIGN):
            if (len(self.args) == 2 and len(self.rop) == 0):
                out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()}"
            elif (len(self.args) == 2 and len(self.rop) > 0):  # e.g. acc = -acc
                out += f"{self.args[0]._debug_vstr()} = {self.rop} {self.args[1]._debug_vstr()}"
            elif (len(self.args) == 3 and len(self.rop) > 0):  # e.g. acc = a1 + a2
                out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()} \
{self.rop} {self.args[2]._debug_vstr()}"
            else:
                out += self._args_and_rop_common_debug_str()
        elif (self.optype == TACTYPE.IMPORT and len(self.args) >= 2):
            out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()}"
        elif (self.optype == TACTYPE.CALL and len(self.args) >= 2):
            if (self.this is not None and len(self.this) > 0):
                out += f"{self.this}->"
            out += f"{self.args[0]._debug_vstr()} args({self.args[1].value}):"
            for i in range(self.args[1].value):
                out += f" {self.args[i + 2]._debug_vstr()},"
        else:
            out += self._args_and_rop_common_debug_str()
        if (self.log is not None and len(self.log) > 0):
            out += f" // {self.log}"
        return out

from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.misc import Log, utils


class TAC(DebugBase):  # Three Address Code
    def __init__(self, optype=TACTYPE.UNKNOWN, args: List[AsmArg] = None, rop="", log: str = "", this: AsmArg = None):
        self.optype = optype
        # === if optype == TACTYPE.CALL # e.g. acc = this->acc(a0, a1...)
        # args[0]: return value stored to # usually acc
        # args[1]: called method
        # args[2]: arg len
        # args[3]: actuall arg0 # args[4] arg1 ...
        # this[opt]: this pointer
        self.args: List[AsmArg] = args
        # rhs op # e.g. acc = a1 + v1 (rop is `+`) acc = -acc (rop is `-`) #  # NOTE: maybe a roptype class?
        self.rop = rop
        self.log: str = log
        self.this: AsmArg = this  # this pointer, maybe point to a object/module

    @property
    def type(self):
        return self.optype

    @property
    def type_str(self) -> str:
        return TACTYPE.get_code_name(self.optype)

    @classmethod
    def tac_assign(cls, dst: AsmArg, src0: AsmArg, src1: AsmArg = None, rop="", log: str = ""):
        if (src1 is None and len(rop) == 0):
            return TAC(TACTYPE.ASSIGN, [dst, src0], log=log)
        if (src1 is None and len(rop) > 0):  # e.g. acc = -acc
            return TAC(TACTYPE.ASSIGN, [dst, src0], rop=rop, log=log)
        assert src1 is not None and rop is not None and len(rop) > 0
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
    def tac_uncn_throw(cls, exception: AsmArg, log: str = ""):
        return TAC(TACTYPE.UNCN_THR, [exception], log=log)

    @classmethod
    def tac_cond_throw(cls, para0: AsmArg, para1: AsmArg, rop, exception: AsmArg, log: str = ""):
        return TAC(TACTYPE.COND_THR, [para0, para1, exception], rop=rop, log=log)

    @classmethod
    def tac_call(cls, arg_len: AsmArg = None, paras: List[AsmArg] = None, this: AsmArg = None,
                 call_addr: AsmArg = None, ret_store_to: AsmArg = AsmArg(AsmTypes.ACC), log: str = ""):
        # call always assign acc = return value # so for all panda call, ret_store_to = acc
        if (call_addr is None):
            call_addr = AsmArg(AsmTypes.ACC)
        return TAC(TACTYPE.CALL, [ret_store_to, call_addr, arg_len, *paras], this=this, log=log)

    @classmethod
    def tac_label(cls, label: AsmArg, log: str = ""):
        return TAC(TACTYPE.LABEL, [label], log=log)

    @classmethod  # TODO: for debug, store some nac and just display it for debug
    def tac_unknown(cls, paras: List[AsmArg] = None, log: str = ""):
        return TAC(TACTYPE.UNKNOWN, paras, log=log)

    def _args_and_rop_common_debug_vstr(self):
        out = f""
        for i in range(len(self.args)):
            out += f"{self.args[i]._debug_vstr()} "
            if (i == 1 and self.rop is not None and len(self.rop) > 0):
                out += f"({self.rop}) "
        return out

    def _debug_str(self):
        out = ""
        if (self.optype == TACTYPE.ASSIGN):
            if (len(self.args) == 2 and len(self.rop) == 0):
                out += f"{self.args[0]} = {self.args[1]}"
            elif (len(self.args) == 2 and len(self.rop) > 0):  # e.g. acc = -acc
                out += f"{self.args[0]} = {self.rop} {self.args[1]}"
            elif (len(self.args) == 3 and len(self.rop) > 0):  # e.g. acc = a1 + a2
                out += f"{self.args[0]} = {self.args[1]} {self.rop} {self.args[2]}"
            else:
                out += self._args_and_rop_common_debug_vstr()
        elif (self.optype == TACTYPE.IMPORT and len(self.args) == 2):
            out += f"{self.args[0]} = {self.args[1]._debug_vstr()}"
        elif (self.optype == TACTYPE.CALL and len(self.args) >= 3):
            if (self.args[0] is not None and len(self.args[0]) > 0):
                out += f"{self.args[0]} = "
            else:
                Log.error(f"self.args[0] is None at a CALL inst. return value store to None?")
            if (self.this is not None and len(self.this) > 0):
                out += f"{self.this}->"
            out += f"{self.args[1]}("
            for i in range(3, len(self.args)):
                out += f"{self.args[i]}, "
            out += ")"
            if (self.args[2] is not None):  # arg len
                out += f"// args({self.args[2].value})"
            else:
                out += f"// args len is None"
        elif (self.optype == TACTYPE.COND_THR and len(self.args) == 3):
            out += f"if({self.args[0]} {self.rop} {self.args[1]}): throw {self.args[2]}"
        elif (self.optype == TACTYPE.UNCN_THR and len(self.args) == 1):
            out += f"throw {self.args[0]}"
        elif (self.optype == TACTYPE.RETURN and len(self.args) == 1):
            out += f"return {self.args[0]}"
        else:
            out += self._args_and_rop_common_debug_vstr()
        if (self.optype == TACTYPE.UNKNOWN):
            out += " //!UNKNOWN TAC"
            if (self.log is not None and len(self.log) > 0):
                out += f" // {self.log}"
        return out

    def _debug_vstr(self):
        out = f"[{TACTYPE.get_code_name(self.optype)}]".ljust(12, " ")
        if (self.optype == TACTYPE.ASSIGN):
            if (len(self.args) == 2 and len(self.rop) == 0):
                out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()}"
            elif (len(self.args) == 2 and len(self.rop) > 0):  # e.g. acc = -acc
                out += f"{self.args[0]._debug_vstr()} = {self.rop} {self.args[1]._debug_vstr()}"
            elif (len(self.args) == 3 and len(self.rop) > 0):  # e.g. acc = a1 + a2
                out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()} \
{self.rop} {self.args[2]._debug_vstr()}"
            else:
                out += self._args_and_rop_common_debug_vstr()
        elif (self.optype == TACTYPE.IMPORT and len(self.args) >= 2):
            out += f"{self.args[0]._debug_vstr()} = {self.args[1]._debug_vstr()}"
        elif (self.optype == TACTYPE.CALL and len(self.args) >= 2):
            if (self.this is not None and len(self.this) > 0):
                out += f"{self.this}->"
            out += f"{self.args[0]._debug_vstr()}("
            for i in range(3, len(self.args)):
                out += f"{self.args[i]._debug_vstr()}, "
            out += ")"
            if (self.args[1] is not None):  # arg len
                out += f"// args({self.args[1].value})"
        elif (self.optype == TACTYPE.COND_THR and len(self.args) == 3):
            out += f"if({self.args[0]._debug_vstr()} {self.rop} {self.args[1]._debug_vstr()}): \
throw {self.args[2]._debug_vstr()}"
        else:
            out += self._args_and_rop_common_debug_vstr()
        if (self.log is not None and len(self.log) > 0):
            out += f" // {self.log}"
        if (self.optype == TACTYPE.UNKNOWN):
            out += " //!UNKNOWN TAC"
        return out

    def get_def_use(self) -> Tuple[set, set]:
        def_vars, use_vars = set(), set()
        # TODO: support array type and ref arg
        if (self.type == TACTYPE.ASSIGN):
            if (len(self.args) == 2):  # a=b
                def_vars.add(self.args[0])
                use_vars.add(self.args[1])
            elif (len(self.args) == 3):  # a=b+c
                def_vars.add(self.args[0])
                use_vars.add(self.args[1])
                use_vars.add(self.args[2])
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.IMPORT):  # acc = module(x)
            if (len(self.args) == 2):
                def_vars.add(self.args[0])
                use_vars.add(self.args[1])
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.COND_JMP):
            if (len(self.args) == 3):
                use_vars.update(self.args)
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.UNCN_JMP):
            if (len(self.args) == 1):
                use_vars.add(self.args[0])
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.LABEL):
            if (len(self.args) == 1):
                use_vars.add(self.args[0])
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.RETURN):
            if (len(self.args) == 1):
                use_vars.add(self.args[0])
            else:
                Log.error(f"get_def_use ERROR {self.type_str} {self._debug_vstr()}")
        elif (self.type == TACTYPE.CALL):
            # call may NOT use acc but will definitely assign/def acc
            use_vars.update(self.args[1:])
            if (self.this is not None):
                assert isinstance(self.this, AsmArg)
                use_vars.add(self.this)
            if (isinstance(self.args[0], AsmArg)):
                def_vars.add(self.args[0])
        elif (self.type == TACTYPE.COND_THR or self.type == TACTYPE.UNCN_THR):
            use_vars.update(self.args)
        else:
            Log.error(f"get_def_use optype NOT SUPPORTED ERROR {self.type_str} {self._debug_vstr()}")
        return def_vars, use_vars

    def is_def(self, rhs: AsmArg) -> bool:
        # return True if rhs is assigned(same as def, which means rhs value would be replaced) at this inst
        if (len(self.args) == 0):
            return False
        def_vars, use_vars = self.get_def_use()
        if (rhs in def_vars):
            return True
        return False

    def is_use(self, rhs: AsmArg) -> bool:
        # return True if rhs is used(which means rhs's value would be read) at this inst
        if (len(self.args) == 0):
            return False
        def_vars, use_vars = self.get_def_use()
        if (rhs in use_vars):
            return True
        return False

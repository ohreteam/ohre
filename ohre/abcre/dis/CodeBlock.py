import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.NACTYPE import NACTYPE
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC


class CodeBlock(DebugBase):  # asm instruction(NAC) cantained
    def __init__(self, in_l: Union[List[List[str]], List[NAC], List[TAC]],
                 prev_cb_list: List = None, next_cb_list: List = None):
        self.insts: Union[List[NAC], List[TAC]] = list()
        if (isinstance(in_l[0], NAC)):  # NAC in list
            self.insts = copy.deepcopy(in_l)
        elif (isinstance(in_l[0], TAC)):  # NAC in list
            self.insts = copy.deepcopy(in_l)
        else:  # maybe list in list # anyway, try init NAC using element in list
            for inst in in_l:
                assert len(inst) > 0
                self.insts.append(NAC(inst))

        self.prev_cb_list: List[CodeBlock] = list()
        if (prev_cb_list is not None):
            self.prev_cb_list = prev_cb_list

        self.next_cb_list: List[CodeBlock] = list()
        if (next_cb_list is not None):
            self.next_cb_list = next_cb_list

        self.use_vars: set[AsmArg] = None
        self.def_vars: set[AsmArg] = None
        self.var2val: Dict[AsmArg, AsmArg] = dict()

    def set_var2val(self, var2val: Dict[AsmArg, AsmArg]):
        self.var2val = var2val

    def get_var2val(self):
        return self.var2val

    def empty_var2val(self):
        self.var2val = dict()

    def get_all_prev_cbs_var2val(self, get_current_cb=False, definite_flag=True) -> Dict[AsmArg, AsmArg]:
        # recursively
        # definite_flag: if True, when var def more than 1 with different value, let var undef
        ret = dict()
        if (get_current_cb):
            ret.update(self.get_var2val())
        for cb in self.prev_cb_list:
            prev_cbs_var2val = cb.get_all_prev_cbs_var2val(True, True)
            for var, val in prev_cbs_var2val.items():
                if (val is None and definite_flag):  # val maybe a return value of call
                    if (val in ret.keys()): # val is None means val is undef-ed
                        del ret[var]
                    continue
                if (val.is_unknown()):
                    continue  # maybe a para of function
                if (definite_flag):
                    if (var not in ret.keys()):
                        ret[var] = val
                    elif (var in ret.keys() and ret[var] == val):  # same value
                        continue
                    else:  # var exist but not same val
                        del ret[var]
                else:
                    ret[var] = val
        return ret

    def get_slice_block(self, idx_start: int, idx_end: int):
        return CodeBlock(copy.deepcopy(self.insts[idx_start: idx_end]))

    def add_next_cb(self, cb):
        if (cb not in self.next_cb_list):
            self.next_cb_list.append(cb)

    def add_prev_cb(self, cb):
        if (cb not in self.prev_cb_list):
            self.prev_cb_list.append(cb)

    def empty_next_cbs(self):
        self.next_cb_list = list()

    def get_all_next_cb(self) -> List:
        return self.next_cb_list

    def set_use_vars(self, use_vars: set):
        self.use_vars = use_vars

    def set_def_vars(self, def_vars: set):
        self.def_vars = def_vars

    def get_use_vars(self) -> set[AsmArg]:
        if (self.use_vars is not None):
            return self.use_vars
        return set()

    def get_def_vars(self) -> set[AsmArg]:
        if (self.def_vars is not None):
            return self.def_vars
        return set()

    def get_all_prev_cbs_def_vars(self, get_current_cb=False) -> set[AsmArg]:
        # recursively
        ret = set()
        if (get_current_cb):
            ret.update(self.get_def_vars())
        for cb in self.prev_cb_list:
            ret.update(cb.get_all_prev_cbs_def_vars(True))
        return ret

    def get_all_next_cbs_use_vars(self, get_current_cb=False) -> set[AsmArg]:
        # recursively
        ret = set()
        if (get_current_cb):
            ret.update(self.get_use_vars())
        for cb in self.next_cb_list:
            ret.update(cb.get_all_next_cbs_use_vars(True))
        return ret

    def is_no_next_cb(self) -> bool:
        if (self.next_cb_list is None or len(self.next_cb_list) == 0):
            return True
        return False

    def replace_insts(self, tac_l: List[TAC]):
        self.insts = tac_l

    def get_insts_len(self) -> int:
        return len(self.insts)

    @property
    def len(self):
        return self.get_insts_len()

    def __len__(self) -> int:
        return self.get_insts_len()

    def _get_short_str_in_list(self, l: List) -> str:
        if (len(l) == 0):
            return ""
        out = f"CB({len(l[0].insts)})"
        for i in range(1, len(l)):
            out += f",CB({len(l[i].insts)})"
        return out

    def _debug_str(self) -> str:
        out = f"CB: insts({len(self.insts)})"
        if (len(self.prev_cb_list)):
            out += f"-[prev_CB:{self._get_short_str_in_list(self.prev_cb_list)}]"
        else:
            out += f"-[NO prev_CB]"
        if (len(self.next_cb_list)):
            out += f"-[next_CB:{self._get_short_str_in_list(self.next_cb_list)}]"
        else:
            out += f"-[NO next_CB]"
        return out

    def _debug_vstr(self) -> str:
        out = self._debug_str() + "\n"
        for i in range(len(self.insts)):
            if (self.insts[i].type == TACTYPE.LABEL):
                out += f"{i}".ljust(4, "-") + f"{self.insts[i]._debug_str()}\n"
            else:
                out += f"{i}".ljust(4, " ") + f"{self.insts[i]._debug_str()}\n"
        return out.strip()

import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.NACTYPE import NACTYPE
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC


class CodeBlock(DebugBase):  # asm instruction(NAC) cantained
    def __init__(self, in_l: Union[List[List[str]], List[NAC], List[TAC]], next_cb_list: set = None):
        assert len(in_l) >= 0
        self.insts: Union[List[NAC], List[TAC]] = list()
        if (isinstance(in_l[0], NAC)):  # NAC in list
            self.insts = copy.deepcopy(in_l)
        elif (isinstance(in_l[0], TAC)):  # NAC in list
            self.insts = copy.deepcopy(in_l)
        else:  # maybe list in list # anyway, try init NAC using element in list
            for inst in in_l:
                assert len(inst) > 0
                self.insts.append(NAC(inst))
        self.next_cb_list: set[CodeBlock] = set()
        if (next_cb_list is None):
            self.next_cb_list = set()
        else:
            self.next_cb_list = next_cb_list

        self.use_vars: set[AsmArg] = None

    def get_slice_block(self, idx_start: int, idx_end: int):
        return CodeBlock(copy.deepcopy(self.insts[idx_start: idx_end]))

    def add_next_cb(self, cb):
        self.next_cb_list.add(cb)

    def empty_next_cbs(self):
        self.next_cb_list = set()

    def get_all_next_cb(self):
        return self.next_cb_list

    def set_use_vars(self, use_vars: set):
        self.use_vars = use_vars

    def get_use_vars(self) -> set[AsmArg]:
        if (self.use_vars is not None):
            return self.use_vars
        return set()

    def get_all_next_cbs_use_vars(self, get_current_cb=False) -> set[AsmArg]:
        # recursively
        ret = set()
        if (get_current_cb):
            ret.update(self.get_use_vars())
        for cb in self.next_cb_list:
            ret.update(cb.get_all_next_cbs_use_vars(True))
        return ret

    def is_no_next_cb(self):
        if (self.next_cb_list is None or len(self.next_cb_list) == 0):
            return True
        return False

    def replace_insts(self, tac_l: List[TAC]):
        self.insts = tac_l

    def get_insts_len(self) -> int:
        return len(self.insts)

    def __len__(self) -> int:
        return len(self.insts)

    def _debug_str(self) -> str:
        out = f"CB: insts({len(self.insts)})"
        if (len(self.next_cb_list)):
            out += f"-[next_CB:{self.next_cb_list}]"
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

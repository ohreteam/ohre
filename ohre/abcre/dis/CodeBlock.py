import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.TAC import TAC


class CodeBlock(DebugBase):  # asm instruction(NAC) cantained
    def __init__(self, in_l: Union[List[List[str]], List[NAC], List[TAC]]):
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

    def get_slice_block(self, idx_start: int, idx_end: int):
        return CodeBlock(copy.deepcopy(self.insts[idx_start: idx_end]))

    def __len__(self) -> int:
        return len(self.insts)

    def _debug_str(self) -> str:
        out = f"CodeBlock: insts {len(self.insts)}"
        return out

    def _debug_vstr(self) -> str:
        out = f"CodeBlock: insts {len(self.insts)}\n"
        for i in range(len(self.insts)):
            if (self.insts[i].type == NACTYPE.LABEL):
                out += f"{i}   {self.insts[i]._debug_vstr()}\n"
            else:
                out += f"{i}\t{self.insts[i]._debug_vstr()}\n"
        return out.strip()

import copy
from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.abcre.dis.TAC import TAC


class CodeBlock():  # asm instruction(NAC) cantained
    def __init__(self, in_l: List[List[str]] | List[NAC] | List[TAC]):
        assert len(in_l) >= 0
        self.insts: List[NAC] | List[TAC] = list()
        if (isinstance(in_l[0], NAC)):  # NAC in list
            self.insts = copy.deepcopy(in_l)
        else:  # maybe list in list # anyway, try init NAC using element in list
            for inst in in_l:
                assert len(inst) > 0
                self.insts.append(NAC(inst))

    def get_slice_block(self, idx_start: int, idx_end: int):
        return CodeBlock(copy.deepcopy(self.insts[idx_start: idx_end]))

    def __str__(self):
        return self.debug_short()

    def __len__(self) -> int:
        return len(self.insts)

    def debug_short(self) -> str:
        out = f"CodeBlock: insts {len(self.insts)}"
        return out

    def debug_deep(self) -> str:
        out = f"CodeBlock: insts {len(self.insts)}\n"
        for i in range(len(self.insts)):
            if (self.insts[i].type == NACTYPE.LABEL):
                out += f"{i}   {self.insts[i].debug_deep()}\n"
            else:
                out += f"{i}\t{self.insts[i].debug_deep()}\n"
        return out.strip()

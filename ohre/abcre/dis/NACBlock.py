import copy
from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE


class NACBlock():  # asm instruction(NAC) cantained
    def __init__(self, in_l: List[List[str]] | List[NAC]):
        assert len(in_l) >= 0
        self.nacs: List[NAC] = list()
        if (isinstance(in_l[0], NAC)):  # NAC in list
            self.nacs = copy.deepcopy(in_l)
        else:  # maybe list in list # anyway, try init NAC using element in list
            for inst in in_l:
                assert len(inst) > 0
                self.nacs.append(NAC(inst))

    def get_slice_block(self, idx_start: int, idx_end: int):
        return NACBlock(copy.deepcopy(self.nacs[idx_start: idx_end]))

    def __str__(self):
        return self.debug_short()

    def __len__(self):
        return len(self.nacs)

    def debug_short(self):
        out = f"NACBlock: nacs {len(self.nacs)}"
        return out

    def debug_deep(self):
        out = f"NACBlock: nacs {len(self.nacs)}\n"
        for i in range(len(self.nacs)):
            if (self.nacs[i].type == NACTYPE.LABEL):
                out += f"{i}   {self.nacs[i].debug_deep()}\n"
            else:
                out += f"{i}\t{self.nacs[i].debug_deep()}\n"
        return out.strip()

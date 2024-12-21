from typing import Any, Dict, Iterable, List, Tuple
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE
import copy


class NACBLOCK_LV:
    NATIVE = 0
    LEVEL1 = 1
    LEVEL2 = 2


class NACBlock():
    def __init__(self, insts: List[List[str]], level=NACBLOCK_LV.NATIVE):
        assert len(insts) > 0
        self.nacs: List[NAC] = list()
        self.level = level
        for inst in insts:
            assert len(inst) > 0
            self.nacs.append(NAC(inst))

    def __str__(self):
        return self.debug_short()

    def debug_short(self):
        out = f"NACBlock: nacs {len(self.nacs)} lv {self.level}"
        return out

    def debug_deep(self):
        out = f"NACBlock: nacs {len(self.nacs)} lv {self.level}\n"
        for i in range(len(self.nacs)):
            out += f"{i}\t{self.nacs[i].debug_deep()}\n"
        return out
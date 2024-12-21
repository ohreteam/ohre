import copy
from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NAC_LV import NAC_LV
from ohre.abcre.dis.NACBlock import NACBlock
from ohre.abcre.dis.NACTYPE import NACTYPE


class NACBlocks():  # NAC block contained, build control flow graph inside a single NACBlocks for one method
    def __init__(self, in_l: List[List[str]] | List[NACBlock]):
        assert len(in_l) >= 0
        self.nac_blocks: List[NACBlock] = list()
        self.IR_lv = NAC_LV.NATIVE  # native

        if (isinstance(in_l[0], NACBlock)):  # NACBlock in list
            self.nac_blocks = copy.deepcopy(in_l)
        else:  # maybe list(str) in list # anyway, try init NACBlock using element(asm codea str list) in list
            self.nac_blocks: List[NACBlock] = [NACBlock(in_l)]

    def __str__(self):
        return self.debug_short()

    @property
    def len(self):
        return len(self.nac_blocks)

    def __len__(self):
        return len(self.nac_blocks)

    def debug_short(self):
        out = f"NACBlocks: nac block({len(self.nac_blocks)}) {NAC_LV.get_code_name(self.IR_lv)}"
        return out

    def debug_deep(self):
        out = f"{self.debug_short()}\n"
        for i in range(len(self.nac_blocks)):
            out += f"[{i}/{len(self.nac_blocks)}]-block: {self.nac_blocks[i].debug_deep()}\n"
        return out

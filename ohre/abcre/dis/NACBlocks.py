from typing import Any, Dict, Iterable, List, Tuple
from ohre.abcre.dis.NACBlock import NACBlock
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE
import copy


class NACBlocks():
    def __init__(self, insts: List[List[str]]):
        self.nac_blocks: List[NACBlock] = [NACBlock(insts)]

    def __str__(self):
        return self.debug_short()

    @property
    def len(self):
        return len(self.nac_blocks)

    def debug_short(self):
        out = f"NACBlocks: block len {len(self.nac_blocks)}"
        return out

    def debug_deep(self):
        out = f"{self.debug_short()}\n"
        for i in range(len(self.nac_blocks)):
            out += f"{i}-block: {self.nac_blocks[i].debug_deep()}\n"
        return out
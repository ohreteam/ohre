import copy
from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.NACTYPE import NACTYPE


class CodeBlocks():  # NAC block contained, build control flow graph inside a single CodeBlocks for one method
    def __init__(self, in_l: List[List[str]] | List[CodeBlock]):
        assert len(in_l) >= 0
        self.blocks: List[CodeBlock] = list()
        self.IR_lv = CODE_LV.NATIVE  # native

        if (isinstance(in_l[0], CodeBlock)):  # CodeBlock in list
            self.blocks = copy.deepcopy(in_l)
        else:  # maybe list(str) in list # anyway, try init CodeBlock using element(asm codea str list) in list
            self.blocks: List[CodeBlock] = [CodeBlock(in_l)]

    def __str__(self):
        return self.debug_short()

    @property
    def len(self):
        return len(self.blocks)

    def __len__(self):
        return len(self.blocks)

    def debug_short(self):
        out = f"CodeBlocks: blocks({len(self.blocks)}) {CODE_LV.get_code_name(self.IR_lv)}"
        return out

    def debug_deep(self):
        out = f"{self.debug_short()}\n"
        for i in range(len(self.blocks)):
            out += f"[{i}/{len(self.blocks)}]-block: {self.blocks[i].debug_deep()}\n"
        return out

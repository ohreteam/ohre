import copy
from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.misc import Log, utils


class CodeBlocks():  # NAC block contained, build control flow graph inside a single CodeBlocks for one method
    def __init__(self, in_l: List[List[str]] | List[CodeBlock], ir_lv=CODE_LV.NATIVE):
        assert len(in_l) >= 0
        self.blocks: List[CodeBlock] = list()
        self.IR_level = ir_lv  # defaul: from native

        if (isinstance(in_l[0], CodeBlock)):  # CodeBlock in list
            self.blocks = copy.deepcopy(in_l)
        else:  # maybe list(str) in list # anyway, try init CodeBlock using element(asm codea str list) in list
            self.blocks: List[CodeBlock] = [CodeBlock(in_l)]

    def __str__(self):
        return self.debug_short()

    @property
    def len(self):
        return len(self.blocks)

    @property
    def level(self):
        return self.IR_level

    @property
    def level_str(self) -> str:
        return CODE_LV.get_code_name(self.IR_level)

    def set_level(self, level):
        if (level >= self.IR_level):
            self.IR_level = level
            return True
        else:
            Log.warn(f"[CodeBlocks] cannot lowering level, level {level} ori {self.IR_level}")
            return False

    def __len__(self) -> int:
        return len(self.blocks)

    def debug_short(self) -> str:
        out = f"CodeBlocks: blocks({len(self.blocks)}) {self.level_str}"
        return out

    def debug_deep(self) -> str:
        out = f"{self.debug_short()}\n"
        for i in range(len(self.blocks)):
            out += f"[{i}/{len(self.blocks)}]-block: {self.blocks[i].debug_deep()}\n"
        return out

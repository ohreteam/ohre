from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.CODE_LV import CODE_LV
from ohre.misc import Log, utils


class CodeBlocks(DebugBase):  # NAC block contained, build control flow graph inside a single CodeBlocks for one method
    def __init__(self, in_l: Union[List[List[str]], List[CodeBlock]], ir_lv=CODE_LV.NATIVE):
        self.blocks: List[CodeBlock] = list()
        self.IR_level = ir_lv  # defaul: from native

        if (isinstance(in_l[0], CodeBlock)):  # CodeBlock in list
            self.blocks = in_l
        else:  # maybe list(str) in list # anyway, try init CodeBlock using element(asm codea str list) in list
            self.blocks: List[CodeBlock] = [CodeBlock(in_l)]

    def __iter__(self):
        return iter(self.blocks)

    @property
    def len(self):
        return len(self.blocks)

    @property
    def level(self):
        return self.IR_level

    @property
    def level_str(self) -> str:
        return CODE_LV.get_code_name(self.IR_level)

    @property
    def inst_len(self):
        return self.get_insts_total()

    def set_level(self, level) -> bool:
        if (level >= self.IR_level):
            self.IR_level = level
            return True
        else:
            Log.warn(f"[CodeBlocks] cannot lowering level, level {level} ori {self.IR_level}")
            return False

    def __len__(self) -> int:
        return len(self.blocks)

    def _debug_str(self) -> str:
        out = f"CodeBlocks: blocks({len(self.blocks)}) {self.level_str} insts-{self.inst_len}"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n"
        for i in range(len(self.blocks)):
            out += f"[{i}/{len(self.blocks)}]-block: {self.blocks[i]._debug_vstr()}\n"
        return out

    def insert_front(self, code_block: CodeBlock):
        self.blocks[0].add_prev_cb(code_block)
        self.blocks.insert(0, code_block)

    def get_insts_total(self) -> int:
        total = 0
        for cb in self.blocks:
            total += cb.get_insts_len()
        return total

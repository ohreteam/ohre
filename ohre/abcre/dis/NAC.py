from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.NACTYPE import NACTYPE


class NAC(DebugBase):  # N Address Code
    # Native representation of ark_disasm-ed ArkTS bytecode
    # corresponding to a single line in a panda function

    def __init__(self, op_args: List[str]):
        assert len(op_args) > 0
        self.op = op_args[0]
        self.type = NACTYPE.get_NAC_type(self.op)
        if (self.type == NACTYPE.LABEL and self.op.endswith(":")):
            self.op = self.op[:-1]
        if (self.type == NACTYPE.TRYCATCH and self.op.endswith("catchall")):
            # fetch catchall sutition, then need to get try_begin_label_0 and try_end_label_0
            self.op = self.op[1:]
        self.args: list = list()
        for i in range(1, len(op_args)):
            self.args.append(op_args[i])

    def _debug_str(self):
        out = f"{self.op} "
        for i in range(len(self.args)):
            if (i == len(self.args) - 1):
                out += f"{self.args[i]}"
            else:
                out += f"{self.args[i]}, "
        return out

    def _debug_vstr(self):
        out = f"({NACTYPE.get_code_name(self.type)}) {self.op} "
        for i in range(len(self.args)):
            if (i == len(self.args) - 1):
                out += f"{self.args[i]}"
            else:
                out += f"{self.args[i]}, "
        return out

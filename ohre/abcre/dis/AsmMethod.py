from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.NativeToTAC import NativeToTAC
from ohre.abcre.dis.ControlFlow import ControlFlow
from ohre.misc import Log, utils


class AsmMethod:
    # fields in Class
    def __init__(self, slotNumberIdx, lines: List[str]):
        assert len(lines) >= 2
        self.slotNumberIdx: int = slotNumberIdx
        self.return_type = "None"
        self.file_name: str = ""
        self.class_func_name: str = ""
        self.func_type: str = ""
        self.args: List = list()
        self.code_blocks: CodeBlocks | None = None
        insts = self._process_method(lines)
        self.code_blocks = CodeBlocks(insts)

    def split_native_code_block(self):
        assert self.code_blocks.level == CODE_LV.NATIVE
        self.code_blocks = ControlFlow.split_native_code_block(self.code_blocks)
        self.code_blocks.set_level(CODE_LV.NATIVE_BLOCK_SPLITED)

    def native_code_to_TAC(self):
        assert self.code_blocks.level == CODE_LV.NATIVE_BLOCK_SPLITED
        self.code_blocks = NativeToTAC.native_code_to_TAC(self.code_blocks)
        self.code_blocks.set_level(CODE_LV.TAC)

    def _process_1st_line(self, line: str):
        parts = line.split(" ")
        assert parts[0] == ".function"
        self.return_type = parts[1].strip()
        file_func_name = parts[2].split("(")[0]
        num = file_func_name.find(".ets")
        if (not num > 0):
            num = file_func_name.find(".src")
        if (num > 0 and num < len(file_func_name) - 5):
            self.file_name = file_func_name[:num + 4]
            self.class_func_name = file_func_name[num + 4 + 1:]
        else:
            self.file_name = file_func_name
            self.class_func_name = file_func_name
        i = len(parts) - 1
        while (i >= 0):
            if (parts[i].startswith("<") and parts[i].endswith(">") and len(parts[i]) >= 3):
                self.func_type = parts[i][1:-1]
                break
            else:
                i -= 1
        # process args now
        parts = line.split("(")
        parts = parts[1].split(")")[0]
        parts = parts.split(",")
        for arg_pair in parts:
            ty, name = arg_pair.strip().split(" ")
            self.args.append((ty, name))

    def _process_method(self, lines: List[str]) -> List[List[str]]:
        insts = list()
        self._process_1st_line(lines[0].strip())
        for line in lines[1:]:
            line = line.strip()
            if (line.endswith(":")):
                if (len(line.split(" ")) == 1):  # single str in a single line endswith ":", maybe label?
                    tu = [line]
                    insts.append(tu)
                else:
                    Log.error(f"ERROR: {line} NOT tag?")
            elif (len(line) == 0):  # skip empty line
                continue
            elif (line == "}"):  # process END
                return insts
            else:  # common situation
                tu = self._process_common_inst(line)
                insts.append(tu)
        return insts

    def _process_common_inst(self, line: str) -> List[str]:
        line = line.strip()
        idx = line.find(" ")
        if (idx < 0):
            ret = [line[:]]
            return ret
        ret = [line[:idx]]  # opcode
        idx += 1
        while (idx < len(line)):
            start_idx = idx
            idx = utils.find_next_delimiter(line, start_idx)
            ret.append(line[start_idx: idx].strip())
            idx = idx + 1
        return ret

    def __str__(self):
        return self.debug_short()

    def debug_short(self) -> str:
        out = f"AsmMethod: {self.slotNumberIdx} {self.func_type} {self.class_func_name} \
ret {self.return_type} file: {self.file_name}\n\
args({len(self.args)}) {self.args} code_blocks({len(self.code_blocks)})"
        return out

    def debug_deep(self) -> str:
        out = f"{self.debug_short()}\n{self.code_blocks.debug_deep()}"
        return out

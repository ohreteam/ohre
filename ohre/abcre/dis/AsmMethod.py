from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.ControlFlow import ControlFlow
from ohre.misc import Log, utils
from ohre.abcre.dis.DebugBase import DebugBase


class AsmMethod(DebugBase):
    # fields in Class
    def __init__(self, slotNumberIdx, lines: List[str]):
        assert len(lines) >= 2
        self.slotNumberIdx: int = slotNumberIdx
        self.return_type = "None"
        self.file_name: str = ""
        self.class_method_name: str = ""
        self.class_name: str = ""  # TODO: split it accurately
        self.method_name: str = ""  # TODO: split it accurately
        self.method_type: str = ""
        self.args: List = list()
        self._process_method_1st_line(lines[0].strip())

        self.code_blocks: Union[CodeBlocks, None] = None
        self.code_blocks = CodeBlocks(self._process_method_inst(lines))

        # for nac tac analysis
        self.cur_module: str = ""

    def _split_class_method_name(self, record_names):
        pass  # TODO: use record_names to split

    def _process_method_1st_line(self, line: str):
        parts = line.split(" ")
        assert parts[0] == ".function"
        self.return_type = parts[1].strip()
        file_func_name = parts[2].split("(")[0]
        file_postfix_idx = file_func_name.find(".ets")
        if (not file_postfix_idx > 0):
            file_postfix_idx = file_func_name.find(".src")
        if (file_postfix_idx > 0 and file_postfix_idx < len(file_func_name) - 5):
            self.file_name = file_func_name[:file_postfix_idx + 4]
            self.class_method_name = file_func_name[file_postfix_idx + 4 + 1:]
        else:
            self.file_name = file_func_name
            self.class_method_name = file_func_name
        if (self.file_name.startswith("&")):
            self.file_name = self.file_name[1:]
        # reverse find: something like <static>
        i = len(parts) - 1
        while (i >= 0):
            if (parts[i].startswith("<") and parts[i].endswith(">") and len(parts[i]) >= 3):
                self.method_type = parts[i][1:-1]
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

    def _process_method_inst(self, lines: List[str]) -> List[List[str]]:
        insts = list()
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
            idx = utils.find_next_delimiter_single_line(line, start_idx)
            ret.append(line[start_idx: idx].strip())
            idx = idx + 1
        return ret

    def _debug_str(self) -> str:
        out = f"AsmMethod: {self.slotNumberIdx} {self.class_method_name} {self.method_type} \
ret {self.return_type} [{self.file_name}] args({len(self.args)}) {self.args} cbs({len(self.code_blocks)})"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n{self.code_blocks._debug_vstr()}"
        return out

    def split_native_code_block(self):
        assert self.code_blocks.level == CODE_LV.NATIVE
        self.code_blocks = ControlFlow.split_native_code_block(self.code_blocks)
        self.code_blocks.set_level(CODE_LV.NATIVE_BLOCK_SPLITED)

    def set_cur_module(self, module_name: str):
        self.cur_module = module_name

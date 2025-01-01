from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.AsmRecord import AsmRecord
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

        dot_function_idx = 0
        while (dot_function_idx < len(lines)):
            parts = lines[dot_function_idx].split(" ")
            if (parts[0] == ".function"):
                break
            dot_function_idx += 1
        if (dot_function_idx != 0):
            print(f"not start with .function: {lines[:dot_function_idx]}")
        self._process_method_1st_line(lines[dot_function_idx].strip())

        self.code_blocks: Union[CodeBlocks, None] = None
        self.code_blocks = CodeBlocks(self._process_method_inst(lines[dot_function_idx + 1:]))

        # for nac tac analysis
        self.cur_module: str = ""
        print(f"init END {self._debug_str()}")

    @property
    def level(self):
        return self.code_blocks.level

    def _split_class_method_name(self, records: List[AsmRecord]):
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
        l_n = 0
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (line.endswith(":")):
                if (len(line.split(" ")) == 1):  # single str in a single line endswith ":", maybe label?
                    tu = [line]
                    insts.append(tu)
                    l_n += 1
                    continue
                else:
                    Log.warn(f"warn: {line} should not be a tag", True)
            if (len(line) == 0):  # skip empty line
                l_n += 1
            elif (line == "}"):  # process END
                return insts
            else:  # common situation
                tu, l_n = self._process_common_inst(lines, l_n)
                insts.append(tu)
        return insts

    def _process_common_inst(self, lines: str, l_n: int) -> Tuple[List[str], int]:
        line = lines[l_n].lstrip()
        line = line.strip()
        idx = line.find(" ")
        if (idx < 0):
            ret = [line[:].strip()]  # only one word # opcode
            return ret, l_n + 1
        ret = [line[:idx]]  # opcode
        idx += 1
        print(f"line-{l_n}: opcode_end_idx {idx} line{len(line)} [{line}] l_n {l_n}")
        opcode_end_idx = idx
        while (True):
            if (idx == -1):
                idx = opcode_end_idx
            idx = utils.find_next_delimiter_single_line(line, idx)
            print(f"line-{l_n}: idx {idx} line{len(line)} [{line}]")
            if (idx == len(line)):
                break
            elif (idx == -1):
                l_n += 1
                line = line + "\n" + lines[l_n]
            else:
                idx += 1
        print(f"line-{l_n}: added, idx {idx} line{len(line)} [{line}]")

        idx = opcode_end_idx
        while (idx < len(line)):
            start_idx = idx
            idx = utils.find_next_delimiter_single_line(line, start_idx)
            ret.append(line[start_idx: idx].strip())
            idx = idx + 1
        print(f"end line-{l_n}: idx {idx} line{len(line)} [{line}] ret {ret} l_n {l_n}")
        return ret, l_n + 1

    def _debug_str(self) -> str:
        out = f"AsmMethod: {self.slotNumberIdx} {self.class_method_name} {self.method_type} ret {self.return_type} \
+[{self.file_name}] args({len(self.args)}) {self.args} cbs({len(self.code_blocks)}) lv {self.level}"
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


if __name__ == "__main__":
    temp = [
        "L_ESSlotNumberAnnotation:",
        "	u32 slotNumberIdx { 0x57 }",
        ".function any com.x.x.entry@aaa.ets.b.c.d.e.func_name(any a0, any a1, any a2, any a3) <static> {",
        "	lda.str \"\"\"",
        "	lda.str \" ",
        " to::\"",
        "	lda.str \"a,b,c: ",
        " to::\"",
        "lda.str \"test3\"\"",
        "defineclasswithbuffer 0x12, &entry.src.main.ets.pages.Index&.#~@0=#Index:(any,any,any,any,any,any,any,any,any), { 13 [ string:\"setInitiallyProvidedValue\", method:#~@0>#setInitiallyProvidedValue, method_affiliate:1, string:\"updateStateVars\", method:#~@0>#updateStateVars, method_affiliate:1, string:\"purgeVariableDependenciesOnElmtId\", method:#~@0>#purgeVariableDependenciesOnElmtId, method_affiliate:1, string:\"aboutToBeDeleted\", method:#~@0>#aboutToBeDeleted, method_affiliate:0, i32:4, ]}, 0x3, v7"
    ]
    method = AsmMethod(0x57, temp[2:])

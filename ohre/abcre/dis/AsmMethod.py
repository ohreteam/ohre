from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.ControlFlow import ControlFlow
from ohre.misc import Log, utils
from ohre.abcre.dis.DebugBase import DebugBase


def is_label_line(s: str):  # single str in a single line endswith ":", maybe label?
    s = s.strip()
    if (s.endswith(":")):
        if (len(s.split(" ")) == 1):  # single str in a single line endswith ":", maybe label?
            return True
    return False


def is_method_end_line(s: str):
    if (s.strip() == "}"):  # process END
        return True
    return False


def find_line_end(lines: List[str], l_n: int):
    l_n_end = l_n + 1
    while (l_n_end < len(lines)):
        if (is_label_line(lines[l_n_end]) or is_method_end_line(lines[l_n_end])):
            break
        if (lines[l_n_end].startswith("\t")):
            break
        l_n_end += 1
    return l_n_end


class AsmMethod(DebugBase):
    # fields in Class
    def __init__(self, slotNumberIdx, lines: List[str]):
        assert len(lines) >= 2
        self.slotNumberIdx: int = slotNumberIdx
        self.return_type = "None"
        self.file_class_method_name: str = ""  # remove the starting "&" if exists
        # the following names is part of this name
        self.file_class_name: str = ""
        self.method_name: str = ""
        self.method_type: str = ""
        self.args: List = list()

        dot_function_idx = 0
        L_ESConcurrentModuleRequestsAnnotation_flag = False
        while (dot_function_idx < len(lines)):
            parts = lines[dot_function_idx].split(" ")
            if ("L_ESConcurrentModuleRequestsAnnotation" in lines[dot_function_idx]):
                L_ESConcurrentModuleRequestsAnnotation_flag = True
            dot_function_idx += 1
        if (dot_function_idx != 0):
            Log.error(f"TODO: not start with .function: {lines[:dot_function_idx]}")
            if (L_ESConcurrentModuleRequestsAnnotation_flag == False):
                Log.error(f"  > d3bug not L_ESConcurrentModuleRequestsAnnotation_flag !!!")
        self._process_method_1st_line(lines[dot_function_idx].strip())

        self.code_blocks: Union[CodeBlocks, None] = None
        self.code_blocks = CodeBlocks(self._process_method_inst(lines[dot_function_idx + 1:]))

        # for nac tac analysis
        self.cur_module: str = ""

    @property
    def level(self):
        return self.code_blocks.level

    def _split_file_class_method_name(self, records: List[AsmRecord]):  # TODO: use record_names to split
        class_name_match_len = 0
        for rec in records:
            if (len(rec.file_class_name) > 0 and self.file_class_method_name.startswith(rec.file_class_name)):
                if (class_name_match_len < len(rec.file_class_name)):
                    class_name_match_len = len(rec.file_class_name)
                    self.file_class_name = rec.file_class_name

                    idx = len(rec.file_class_name)
                    if (self.file_class_method_name[idx] == "&"):
                        idx += 1
                    if (self.file_class_method_name[idx] == "."):
                        idx += 1
                    self.method_name = self.file_class_method_name[idx:]
        if (class_name_match_len == 0):
            Log.error(
                f"_split_file_class_method_name ERROR, NOT match, file_class_method_name {self.file_class_method_name}")

    def _process_method_1st_line(self, line: str):
        parts = line.split(" ")
        assert parts[0] == ".function"
        self.return_type = parts[1].strip()
        file_func_name = parts[2].split("(")[0]
        self.file_class_method_name = file_func_name.strip()
        if (self.file_class_method_name.startswith("&")):
            self.file_class_method_name = self.file_class_method_name[1:]
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
            line: str = lines[l_n]
            if (is_label_line(line)):
                insts.append([line])
                l_n += 1
            if (len(line.strip()) == 0):  # skip empty line
                l_n += 1
            elif (is_method_end_line(line)):  # process END
                return insts
            else:  # common situation
                tu, l_n = self._process_common_inst(lines, l_n)
                insts.append(tu)
        return insts

    def _process_ldastr(self, lines: str, l_n: int) -> Tuple[List[str], int]:
        ret = ["lda.str"]  # opcode
        l_n_end = find_line_end(lines, l_n)
        line_concat = lines[l_n].lstrip()
        for i in range(l_n + 1, l_n_end):
            line_concat += "\n" + lines[i]
        s_idx = line_concat.find("lda.str") + len("lda.str")
        s_idx = line_concat.find("\"", s_idx) + 1
        e_idx = line_concat.rfind("\"")
        ret.append(line_concat[s_idx: e_idx])
        return ret, l_n_end

    def _process_createobjectwithbuffer(self, lines: str, l_n: int) -> Tuple[List[str], int]:
        ret = ["createobjectwithbuffer"]  # opcode
        l_n_end = find_line_end(lines, l_n)
        line_concat = lines[l_n].lstrip()
        for i in range(l_n + 1, l_n_end):
            line_concat += "\n" + lines[i]
        s_idx = line_concat.find("createobjectwithbuffer") + len("createobjectwithbuffer")
        idx = utils.find_next_delimiter_single_line(line_concat, s_idx)
        ret.append(line_concat[s_idx: idx].strip())  # reserved number

        s_idx = line_concat.find("\{", idx) + 1
        e_idx = line_concat.rfind("\}")
        ret.append(line_concat[s_idx: e_idx])
        return ret, l_n_end
    def _process_common_inst(self, lines: str, l_n: int) -> Tuple[List[str], int]:
        line = lines[l_n].lstrip()
        idx = line.find(" ")
        if (idx < 0):
            ret = [line[:].strip()]  # only one word # opcode
            return ret, l_n + 1
        ret = [line[:idx]]  # opcode
        if (line[:idx] == "lda.str"):
            return self._process_ldastr(lines, l_n)
        if (line[:idx] == "createobjectwithbuffer"):
            return self._process_createobjectwithbuffer(lines, l_n)
        idx += 1

        opcode_end_idx = idx
        while (True):
            if (idx == -1):
                idx = opcode_end_idx
            idx = utils.find_next_delimiter_single_line(line, idx)
            if (idx == len(line)):
                break
            elif (idx == -1):
                l_n += 1
                line = line + "\n" + lines[l_n]
            else:
                idx += 1

        idx = opcode_end_idx
        while (idx < len(line)):
            start_idx = idx
            idx = utils.find_next_delimiter_single_line(line, start_idx)
            ret.append(line[start_idx: idx].strip())
            idx = idx + 1
        return ret, l_n + 1

    def _debug_str(self) -> str:
        out = f"AsmMethod: {self.slotNumberIdx} {self.file_class_method_name} method_name {self.method_name} \
{self.method_type} ret {self.return_type} [{self.file_class_name}] \
args({len(self.args)}) {self.args} cbs({len(self.code_blocks)}) lv {self.level}"
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

from typing import Any, Dict, Iterable, List, Tuple
from ohre.misc import Log
from ohre.abcre.dis.AsmTypes import AsmTpye


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
        self.insts: List = list()
        self._process_method(lines)

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

    def _process_method(self, lines: List[str]):
        self._process_1st_line(lines[0].strip())
        for line in lines[1:]:
            line = line.strip()
            if (line.endswith(":")):
                if (len(line.split(" ")) == 1):
                    tu = [line]
                    self.insts.append(tu)
                else:
                    Log.error(f"ERROR: {line} NOT tag?", True)
            elif (len(line) == 0):
                continue
            elif (line == "}"):
                return
            else:
                tu = list(line.split(" "))
                for i in range(len(tu)):
                    if (tu[i].endswith(",")):
                        tu[i] = tu[i][:-1]
                self.insts.append(tu)

    def __str__(self):
        return self.debug_short()

    def debug_short(self) -> str:
        out = f"AsmMethod: {self.slotNumberIdx} {self.func_type} {self.class_func_name}  file: {self.file_name}\n\
args({len(self.args)}) {self.args} insts({len(self.insts)})"
        return out

    def debug_deep(self) -> str:
        out_insts = ""
        for line_num in range(len(self.insts)):
            inst = self.insts[line_num]
            out = f"{line_num}\t{inst[0]} "
            for i in range(1, len(inst)):
                if (i != len(inst) - 1):
                    out += f"{inst[i]}, "
                else:
                    out += f"{inst[i]}"
            out_insts += f"{out}\n"
        out = f"AsmMethod: {self.slotNumberIdx} {self.func_type} {self.class_func_name}  file: {self.file_name}\n\
args({len(self.args)}) {self.args} insts({len(self.insts)})\n{out_insts}"
        return out

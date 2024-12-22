from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.AsmString import AsmString
from ohre.misc import Log


class STATE:
    INIT = 0
    NEW_SEC = 1
    LITERALS = 2
    RECORDS = 3
    METHODS = 4
    STRING = 5


def _is_delimiter(s: str) -> bool:
    if (s.startswith("# ")):
        if (s.strip().endswith("====================")):
            return True
    return False


class DisFile():
    def __init__(self, value):
        self.source_binary_name: str = ""
        self.language: str = ""
        self.lines: List[str] = list()
        self.records: List[AsmRecord] = list()
        self.methods: List[AsmMethod] = list()
        self.asmstrs: List[AsmString] = list()
        if (isinstance(value, str)):
            file = open(value, "r", encoding="utf-8", errors="ignore")
            for line in file:
                self.lines.append(line)
            file.close()
        else:
            Log.error(f"DisFile init ERROR: value type NOT supported, {type(value)} {value}")
        self._dis_process_main()

    def _dis_process_main(self):
        l_n = 0  # line number
        state = STATE.INIT
        while (l_n < len(self.lines)):
            Log.info(f"DisFile processing: state {state} line-{l_n}: {self.lines[l_n].rstrip()}")
            if (state == STATE.INIT):
                state, l_n = self._read_disheader(l_n)
            elif (state == STATE.NEW_SEC):
                state, l_n = self._read_section_type(l_n)
            elif (state == STATE.LITERALS):
                state, l_n = self._read_literals(l_n)
            elif (state == STATE.RECORDS):
                state, l_n = self._read_records(l_n)
            elif (state == STATE.METHODS):
                state, l_n = self._read_methods(l_n)
            elif (state == STATE.STRING):
                state, l_n = self._read_strings(l_n)
            else:
                Log.error(f"state ERROR, state {state} l_n {l_n}")
                return
        Log.info(f"DisFile process END, l_n {l_n} should >= {len(self.lines)}")

    def _read_section_type(self, l_n) -> Tuple[int, int]:
        line: str = self.lines[l_n].strip()
        if (line.startswith("# ") and len(line) > 3):
            if (line[2:] == "LITERALS"):
                return STATE.LITERALS, l_n + 1
            if (line[2:] == "RECORDS"):
                return STATE.RECORDS, l_n + 1
            if (line[2:] == "METHODS"):
                return STATE.METHODS, l_n + 1
            if (line[2:] == "STRING"):
                return STATE.STRING, l_n + 1
        Log.error(f"cannot determint what section is, line: {line}")
        return None, len(self.lines)

    def _read_disheader(self, l_n) -> Tuple[int, int]:
        while (l_n < len(self.lines)):
            line: str = self.lines[l_n].strip()
            if (_is_delimiter(line)):
                return STATE.NEW_SEC, l_n + 1
            elif (line.startswith("# ")):
                if ("source binary:" in line):
                    self.source_binary_name = line.split(":")[1].strip()
            elif (line.startswith(".language")):
                self.language = line.split(" ")[1].strip()
            elif (len(line) == 0):
                pass
            else:
                Log.error(f"ERROR in _read_disheader, else hit. line {line}")
            l_n += 1

    def _read_literals(self, l_n) -> Tuple[int, int]:
        while (l_n < len(self.lines)):
            line: str = self.lines[l_n].strip()
            if (_is_delimiter(line)):
                return STATE.NEW_SEC, l_n + 1
            l_n += 1
        return None, l_n + 1

    def _read_records(self, l_n) -> Tuple[int, int]:
        while (l_n < len(self.lines)):
            line: str = self.lines[l_n].strip()
            if (_is_delimiter(line)):
                return STATE.NEW_SEC, l_n + 1
            elif (line.strip().startswith(".record")):
                lines_record: List[str] = list()
                while (l_n < len(self.lines)):  # find "}"
                    line_rec: str = self.lines[l_n].rstrip()
                    lines_record.append(line_rec)
                    l_n += 1
                    if ("}" in line_rec):
                        break
                rec = AsmRecord(lines_record)
                self.records.append(rec)
            else:
                l_n += 1
        return None, l_n + 1

    def _read_methods(self, l_n) -> Tuple[int, int]:
        while (l_n < len(self.lines)):
            line: str = self.lines[l_n].strip()
            if (_is_delimiter(line)):
                return STATE.NEW_SEC, l_n + 1
            elif (line == "L_ESSlotNumberAnnotation:"):
                l_n += 1
                line: str = self.lines[l_n].strip()
                parts = line.strip().split(" ")
                slotNumberIdx = int(parts[-2], 16)
                l_n += 1
                lines_method: List[str] = list()
                while (l_n < len(self.lines)):  # find "}"
                    line_method: str = self.lines[l_n].rstrip()
                    lines_method.append(line_method)
                    l_n += 1
                    if ("}" == line_method):
                        break
                method = AsmMethod(slotNumberIdx, lines_method)
                self.methods.append(method)
            else:
                l_n += 1
        return None, l_n + 1

    def _read_strings(self, l_n) -> Tuple[int, int]:
        while (l_n < len(self.lines)):
            line: str = self.lines[l_n].strip()
            if (_is_delimiter(line)):
                return STATE.NEW_SEC, l_n + 1
            elif (len(line) == 0):
                pass
            elif (line.startswith("[") and line.endswith("]") and len(line) > 6):
                asmstr = AsmString(line[1:-1])
                self.asmstrs.append(asmstr)
            else:
                Log.error(f"ERROR in _read_strings, else hit. line {line}")
            l_n += 1
        return None, l_n + 1

    def __str__(self):
        return self.debug_short()

    def debug_short(self) -> str:
        out = f"DisFile: {self.source_binary_name} language {self.language} lines({len(self.lines)}) \
records({len(self.records)}) methods({len(self.methods)}) asmstrs({len(self.asmstrs)})"
        return out

    def debug_deep(self) -> str:
        out = self.debug_short() + "\n"
        for rec in self.records:
            out += f">> {rec.debug_deep()}\n"
        for method in self.methods:
            out += f">> {method.debug_deep()}\n"
        for asmstr in self.asmstrs:
            out += f">> {asmstr}\n"
        return out

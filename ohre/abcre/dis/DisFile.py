from threading import Thread
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmLiteral import AsmLiteral
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.AsmString import AsmString
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


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


class DisFile(DebugBase):
    def __init__(self, value):
        self.source_binary_name: str = ""
        self.language: str = ""
        self.literals: List[AsmLiteral] = list()
        self.records: List[AsmRecord] = list()
        self.methods: List[AsmMethod] = list()
        self.asmstrs: List[AsmString] = list()
        lines: List[str] = list()
        if (isinstance(value, str)):
            file = open(value, "r", encoding="utf-8", errors="ignore")
            for line in file:
                lines.append(line)
            file.close()
        else:
            Log.error(f"DisFile init ERROR: value type NOT supported, {type(value)} {value}")
        self._dis_process_main(lines)

    def _dis_process_main(self, lines: List[str]):
        process_list: List[Thread] = [Thread(target=self._read_disheader, args=(0, lines))]
        l_n = 0  # line number
        while (l_n < len(lines)):
            if (_is_delimiter(lines[l_n].strip())):
                l_n += 1
                state, l_n = self._read_section_type(l_n, lines)
                if (state == STATE.LITERALS):
                    process_list.append(Thread(target=self._read_literals, args=(l_n, lines)))
                elif (state == STATE.RECORDS):
                    process_list.append(Thread(target=self._read_records, args=(l_n, lines)))
                elif (state == STATE.METHODS):
                    process_list.append(Thread(target=self._read_methods, args=(l_n, lines)))
                elif (state == STATE.STRING):
                    process_list.append(Thread(target=self._read_strings, args=(l_n, lines)))
                else:
                    Log.error(f"state ERROR, state {state} l_n {l_n}")
            l_n += 1
        Log.info(f"DisFile process threads START, l_n {l_n} should >= {len(lines)}")
        for process in process_list:
            process.start()
        for process in process_list:
            process.join()  # wait for all process
        Log.info(f"DisFile process END")

    def _read_section_type(self, l_n: int, lines: List[str]) -> Tuple[int, int]:
        line: str = lines[l_n].strip()
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
        return None, len(lines)

    def _read_disheader(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
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

    def _read_literals(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            parts = line.split(" ")
            if (parts[0].isdigit()):
                l_idx, n_idx = utils.find_matching_symbols_multi_line(lines[l_n:], "{")
                if (l_idx is not None):
                    asm_lit = AsmLiteral(lines[l_n:l_n + l_idx + 1])
                    self.literals.append(asm_lit)
                l_n += l_idx + 1
            else:
                l_n += 1

    def _read_records(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            elif (line.startswith(".record")):
                lines_record: List[str] = list()
                while (l_n < len(lines)):  # find "}"
                    line_rec: str = lines[l_n].rstrip()
                    lines_record.append(line_rec)
                    l_n += 1
                    if ("}" in line_rec):
                        break
                rec = AsmRecord(lines_record)
                self.records.append(rec)
            else:
                l_n += 1

    def _read_methods(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            elif (line == "L_ESSlotNumberAnnotation:"):
                l_n += 1
                line: str = lines[l_n].strip()
                parts = line.strip().split(" ")
                slotNumberIdx = int(parts[-2], 16)
                l_n += 1
                lines_method: List[str] = list()
                while (l_n < len(lines)):  # find "}"
                    line_method: str = lines[l_n].rstrip()
                    lines_method.append(line_method)
                    l_n += 1
                    if ("}" == line_method):
                        break
                method = AsmMethod(slotNumberIdx, lines_method)
                self.methods.append(method)
            else:
                l_n += 1

    def _read_strings(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            elif (len(line) == 0):
                l_n += 1
            elif (line.startswith("[")): # single or multi line
                l_idx, n_idx = utils.find_matching_symbols_multi_line(lines[l_n:], "[")
                if (l_idx is not None):
                    asmstr = AsmString(lines[l_n:l_n + l_idx + 1])
                    self.asmstrs.append(asmstr)
                    l_n += l_idx + 1
            else:
                Log.error(f"ERROR in _read_strings, else hit. l_n {l_n} line {line}")
                l_n += 1
        return None, l_n + 1

    def _debug_str(self) -> str:
        out = f"DisFile: {self.source_binary_name} language {self.language} \
literals({len(self.literals)}) records({len(self.records)}) methods({len(self.methods)}) asmstrs({len(self.asmstrs)})"
        return out

    def _debug_vstr(self) -> str:
        out = self._debug_str() + "\n"
        for lit in self.literals:
            out += f">> {lit._debug_vstr()}\n"
        for rec in self.records:
            out += f">> {rec._debug_vstr()}\n"
        for method in self.methods:
            out += f">> {method._debug_vstr()}\n"
        for asmstr in self.asmstrs:
            out += f">> {asmstr._debug_vstr()}\n"
        return out

    def get_literal_by_addr(self, addr: int) -> Union[AsmLiteral, None]:
        for lit in self.literals:
            if (lit.address == addr):
                return lit
        return None

    def get_external_module_name(
            self, index: int, file_name: str = "", class_method_name: str = "", class_name: str = "") -> Union[str, None]:
        hit_cnt = 0
        hit_rec: AsmRecord = None
        if (len(file_name) > 0 and len(class_method_name) > 0):
            for rec in self.records:
                if (file_name == rec.file_name and rec.class_name in class_method_name):
                    hit_cnt += 1
                    hit_rec = rec
            if (hit_cnt == 1):
                if ("moduleRecordIdx" in hit_rec.fields.keys()):
                    ty, addr = hit_rec.fields["moduleRecordIdx"]
                    lit = self.get_literal_by_addr(addr)
                    if (lit is not None):
                        return lit.module_request_array[index]
            else:
                Log.warn(f"get_external_module_name failed, hit_cnt {hit_cnt} \
file_name {file_name} class_method_name {class_method_name}", True)
        return None

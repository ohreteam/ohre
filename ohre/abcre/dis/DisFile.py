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
        self._debug: List = None
        self.lex_env: List = list()
        self.cur_lex_level: int = 0
        # module_name : dict{ var_name: set{potential values of var_name} }
        self.modulevar_d: Dict[str, Dict[str, set]] = dict()

        lines: List[str] = list()
        if (isinstance(value, str)):
            file = open(value, "r", encoding="utf-8", errors="ignore")
            lines = file.readlines()
            file.close()
        else:
            Log.error(f"DisFile init ERROR: value type NOT supported, {type(value)} {value}")

        self._dis_process_main(lines)
        for method in self.methods:
            method._split_file_class_method_name(self.records)

    def _dis_process_main(self, lines: List[str]):
        process_list: List[Thread] = [Thread(target=self._read_disheader, args=(0, lines))]
        l_n = 0  # line number
        lit_ln_start, rec_ln_start, met_ln_start, str_ln_start = 0, 0, 0, 0
        while (l_n < len(lines)):
            if (_is_delimiter(lines[l_n].strip())):
                l_n += 1
                state, l_n = self._read_section_type(l_n, lines)
                if (state == STATE.LITERALS):
                    lit_ln_start = l_n
                    process_list.append(Thread(target=self._read_literals, args=(l_n, lines)))
                elif (state == STATE.RECORDS):
                    rec_ln_start = l_n
                    process_list.append(Thread(target=self._read_records, args=(l_n, lines)))
                elif (state == STATE.METHODS):
                    met_ln_start = l_n
                    process_list.append(Thread(target=self._read_methods, args=(l_n, lines)))
                elif (state == STATE.STRING):
                    str_ln_start = l_n
                    process_list.append(Thread(target=self._read_strings, args=(l_n, lines)))
                else:
                    Log.error(f"state ERROR, state {state} l_n {l_n}")
            else:
                l_n += 1
        process_list.append(Thread(target=self._count_parts, args=(
            lines, lit_ln_start, rec_ln_start, met_ln_start, str_ln_start)))
        Log.info(f"DisFile process threads START, l_n {l_n} should >= {len(lines)}")
        for process in process_list:
            process.start()
        for process in process_list:
            process.join()  # wait for all process
        Log.info(f"DisFile process END, abc file name {self.source_binary_name}")

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

    def _count_parts(self, lines: List[str], lit_ln_start, rec_ln_start, met_ln_start, str_ln_start):
        # debug # for checking the subtotal of different parts
        assert lit_ln_start < rec_ln_start and rec_ln_start < met_ln_start and met_ln_start < str_ln_start
        cnt_lit, cnt_rec, cnt_met, cnt_str = 0, 0, 0, 0
        cnt_debug = 0
        for i in range(lit_ln_start, rec_ln_start):
            parts = lines[i].split(" ")
            if (len(parts) and parts[0].isdigit() and lines[i][0].isdigit()):
                cnt_lit += 1
        for i in range(rec_ln_start, met_ln_start):
            if (lines[i].startswith(".record ")):
                cnt_rec += 1
        for i in range(met_ln_start, str_ln_start):
            if (lines[i].startswith("L_ESSlotNumberAnnotation:")):
                cnt_met += 1
            if (lines[i] == "\n"):
                cnt_debug += 1
        for i in range(str_ln_start, len(lines)):
            if (lines[i].startswith("[offset:")):
                cnt_str += 1
        self._debug = [cnt_lit, cnt_rec, cnt_met, cnt_str, cnt_debug]

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
        def find_next_string_line(l_n: int, lines: List[str]) -> int:
            l_n_end = l_n + 1
            while (l_n_end < len(lines)):
                if (lines[l_n_end].startswith("[offset:")):
                    return l_n_end
                l_n_end += 1
            return len(lines)
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            elif (len(line) == 0):
                l_n += 1
            elif (line.startswith("[offset:")):  # single or multi line
                l_n_next = find_next_string_line(l_n, lines)
                line_concat = lines[l_n]
                for i in range(l_n + 1, l_n_next):
                    line_concat += "\n" + lines[i]
                asmstr = AsmString(line_concat)
                self.asmstrs.append(asmstr)
                l_n = l_n_next
            else:
                Log.error(f"ERROR in _read_strings, else hit. l_n {l_n} line {line}")
                l_n += 1
        return None, l_n + 1

    def _debug_str(self) -> str:
        out = f"DisFile: {self.source_binary_name} language {self.language} \
literals({len(self.literals)}) records({len(self.records)}) methods({len(self.methods)}) asmstrs({len(self.asmstrs)}) \
_debug {self._debug}"
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

    @property
    def dis_name(self) -> str:
        return self.source_binary_name + ".dis"

    def get_abc_name(self) -> str:
        return self.source_binary_name

    def get_literal_by_addr(self, addr: int) -> Union[AsmLiteral, None]:
        for lit in self.literals:
            if (lit.address == addr):
                return lit
        return None

    def get_records_by_module_name(self, module_name: str) -> List[AsmRecord]:
        ret: List[AsmRecord] = list()
        if (len(module_name) > 0):
            for rec in self.records:
                if (module_name == rec.module_name):
                    ret.append(rec)
        return ret

    def get_record_by_module_name(self, module_name: str) -> AsmRecord:
        hit_cnt = 0
        hit_rec: AsmRecord = None
        for rec in self.records:
            if (module_name == rec.module_name):
                hit_cnt += 1
                hit_rec = rec
        if (hit_cnt > 1):
            Log.warn(f"get_record_by_module_name hit_cnt > 1, hit_cnt {hit_cnt} module_name {module_name}", True)
        return hit_rec

    def get_external_module_name(self, index: int, module_name: str = "") -> Union[str, None]:
        hit_rec = None
        if (len(module_name) > 0):
            hit_rec = self.get_record_by_module_name(module_name)
            if (hit_rec is not None and "moduleRecordIdx" in hit_rec.fields.keys()):
                ty, addr = hit_rec.fields["moduleRecordIdx"]
                lit = self.get_literal_by_addr(addr)
                if (lit is not None and index >= 0 and index < len(lit.module_tags)):
                    if (isinstance(lit.module_tags[index], dict)
                            and "module_request" in lit.module_tags[index].keys()):
                        return lit.module_tags[index]["module_request"]
        Log.warn(f"get_external_module_name failed, module_name {module_name} hit_rec {hit_rec}", True)
        return None

    def get_local_module_name(self, index: int, module_name: str = "") -> Union[str, None]:
        hit_rec = None
        if (len(module_name) > 0):
            hit_rec = self.get_record_by_module_name(module_name)
            if (hit_rec is not None and "moduleRecordIdx" in hit_rec.fields.keys()):
                ty, addr = hit_rec.fields["moduleRecordIdx"]
                lit = self.get_literal_by_addr(addr)
                if (lit is not None and index >= 0 and index < len(lit.module_tags)):
                    idx_in_lit = 0
                    for d in lit.module_tags[index]:
                        if (isinstance(d, dict) and "ModuleTag" in d.keys() and d["ModuleTag"] == "LOCAL_EXPORT"):
                            if (idx_in_lit == index and "local_name" in d.keys()):
                                if ("export_name" in d.keys() and d["local_name"] != d["export_name"]):
                                    Log.warn(f"local_module {d['local_name']} != {d['export_name']}")
                                return d["local_name"]
                            idx_in_lit += 1
        Log.warn(f"get_local_module_name failed, module_name {module_name} hit_rec {hit_rec}", True)
        return None

    def create_lexical_environment(
            self, slots: int, literal_id=None) -> Union[str, None]:
        slots_number = slots
        lex_env_layer = [None] * slots_number
        if literal_id:
            left_s = literal_id.find('[')
            right_s = literal_id.find(']')
            literal_content = literal_id[left_s:right_s + 1]
            literal_content = literal_content.split(',')
            cnt = 0
            for i in range(slots_number):
                literal_value = literal_content[cnt].strip().split(':')
                if len(literal_value) == 2:
                    variable_value = literal_value[1].replace('"', '')
                else:
                    Log.warn(f"newlexenvwithname failed. literal id format is {literal_content[cnt]}")
                variable_name = literal_content[cnt + 1].strip().split(':')
                if len(variable_name) == 2:
                    variable_name = variable_name[1].replace('"', '')
                else:
                    Log.warn(f"newlexenvwithname failed. literal id format is {literal_content[cnt + 1]}")
                # lex_env_layer[i] = f"[variable: {variable_name} value: {variable_value}]"
                lex_env_layer[i] = variable_name
                cnt += 2
        self.lex_env.append(lex_env_layer)
        self.cur_lex_level += 1
        return self.lex_env[-1]

    def get_lex_env(
            self, lexenv_layer: int, slot_index: int
    ):
        fetch_lex_env_index = self.cur_lex_level - 1 - lexenv_layer
        if fetch_lex_env_index >= 0:
            return self.lex_env[fetch_lex_env_index][slot_index]
        else:
            Log.warn(f"get_lex_env failed, cur_lex {self.cur_lex_level}.\
                     Wanted fetch level {fetch_lex_env_index}")
            return None

    def pop_lex_env(self):
        if len(self.lex_env) == 0:
            Log.warn(f"pop_lex_env failed, self.lex_env is empty")
        else:
            self.lex_env.pop()
            self.cur_lex_level -= 1

    def _module_var_name_preprocess(self, var_name: str) -> str:
        if (var_name.startswith("__")):
            return var_name[2:]
        return var_name

    def new_module_var(self, module_name: str, var_name: str, var_value=None):
        var_name = self._module_var_name_preprocess(var_name)
        if (module_name not in self.modulevar_d.keys()):
            self.modulevar_d[module_name] = dict()
        if (var_name not in self.modulevar_d[module_name].keys()):
            self.modulevar_d[module_name][var_name] = set()
        if (var_value is not None):
            self.modulevar_d[module_name][var_name].add(var_value)

    def set_module_var(self, module_name: str, var_name: str, var_value):
        self.new_module_var(module_name, var_name, var_value)

    def get_module_var_values(self, module_name: str, var_name: str) -> Iterable:
        var_name = self._module_var_name_preprocess(var_name)
        if (module_name in self.modulevar_d.keys() and var_name not in self.modulevar_d[module_name].keys()):
            return self.modulevar_d[module_name][var_name]
        return None

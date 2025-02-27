from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmLiteral import AsmLiteral
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.AsmString import AsmString
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.ModuleInfo import ModuleInfo
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
        self.literals: Dict[str, AsmLiteral] = dict()  # addr -> lit
        self.records: Dict[str, AsmRecord] = dict()  # module_name -> rec
        self.methods: Dict[str, Dict[str, AsmMethod]] = dict()  # module_name -> method_name -> AsmMethod
        self.asmstrs: List[AsmString] = list()
        self._debug: List = None
        self.lex_env: List = list()
        self.cur_lex_level: int = 0
        # module_name -> ModuleInfo
        self.module_info: Dict[str, ModuleInfo] = dict()
        lines: List[str] = list()
        if (isinstance(value, str)):
            file = open(value, "r", encoding="utf-8", errors="ignore")
            lines = file.readlines()
            file.close()
        else:
            Log.error(f"DisFile init ERROR: value type NOT supported, {type(value)} {value}")

        self._dis_process_main(lines)
        for module_name in self.methods.keys():
            self.module_info[module_name] = ModuleInfo(module_name)
            hit_rec: AsmRecord = self.get_record_by_module_name(module_name)
            if (hit_rec is not None and "moduleRecordIdx" in hit_rec.fields):
                ty, addr = hit_rec.fields["moduleRecordIdx"]
                lit = self.get_literal_by_addr(addr)
                if (lit is not None):
                    self._ini_modulevar_local(module_name, lit)

    def _dis_process_main(self, lines: List[str]):
        l_n = 0  # line number
        lit_ln_start, rec_ln_start, met_ln_start, str_ln_start = 0, 0, 0, 0
        Log.info(f"DisFile process START", True)
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.submit(self._read_disheader, 0, lines)
            while (l_n < len(lines)):
                if (_is_delimiter(lines[l_n].strip())):
                    l_n += 1
                    state, l_n = self._read_section_type(l_n, lines)
                    if (state == STATE.LITERALS):
                        lit_ln_start = l_n
                        executor.submit(self._read_literals, l_n, lines)
                    elif (state == STATE.RECORDS):
                        rec_ln_start = l_n
                        executor.submit(self._read_records, l_n, lines)
                    elif (state == STATE.METHODS):
                        met_ln_start = l_n
                        executor.submit(self._read_methods, l_n, lines)
                    elif (state == STATE.STRING):
                        str_ln_start = l_n
                        executor.submit(self._read_strings, l_n, lines)
                    else:
                        Log.error(f"state ERROR, state {state} l_n {l_n}")
                else:
                    l_n += 1
            executor.submit(self._count_parts, lines, lit_ln_start, rec_ln_start, met_ln_start, str_ln_start)
        Log.info(f"DisFile process END, {l_n}>={len(lines)}? {self._debug_str()} _debug {self._debug}", True)

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
            line: str = lines[l_n]
            if (_is_delimiter(line)):
                Log.info(f"_read_literals END")
                return
            parts = line.split(" ")
            if (parts[0].isdigit()):
                l_idx, n_idx = utils.find_matching_symbols_multi_line(lines[l_n:], "{")
                if (l_idx is not None):
                    asm_lit = AsmLiteral(lines[l_n:l_n + l_idx + 1])
                    self.literals[asm_lit.address] = asm_lit
                l_n += l_idx + 1
            else:
                l_n += 1

    def _read_records(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n]
            if (_is_delimiter(line)):
                return
            elif (line.startswith(".record")):
                end_ln = lines.index("}\n", l_n + 1)
                rec = AsmRecord(lines[l_n:end_ln + 1])
                self.records[rec.module_name] = rec
                l_n = end_ln + 1
            else:
                l_n += 1

    def _read_methods(self, l_n: int, lines: List[str]):
        while (l_n < len(lines)):
            line: str = lines[l_n].strip()
            if (_is_delimiter(line)):
                return
            elif (line == "L_ESSlotNumberAnnotation:"):
                try:
                    next_TAG_ln = lines.index("L_ESSlotNumberAnnotation:\n", l_n + 1)
                    lines_method = lines[l_n:next_TAG_ln]
                    for i, sub_l in enumerate(lines_method):
                        lines_method[i] = sub_l.rstrip()
                    meth = AsmMethod(lines_method)
                    l_n = next_TAG_ln - 1
                except Exception as e:
                    Log.info(f"_read_methods exception {e}, should be last meth: l_n {l_n} {lines[l_n:l_n + 4]}")
                    lines_method: List[str] = list()
                    while (l_n < len(lines)):  # find "}"
                        line_method: str = lines[l_n].rstrip()
                        lines_method.append(line_method)
                        l_n += 1
                        if ("}" == line_method):
                            break
                    meth = AsmMethod(lines_method)
                if (meth.module_name not in self.methods):
                    self.methods[meth.module_name] = dict()
                self.methods[meth.module_name][meth.method_name] = meth
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
            line: str = lines[l_n]
            if (_is_delimiter(line)):
                return
            elif (len(line) == 0):
                l_n += 1
            elif (line.startswith("[offset:")):  # single or multi line
                l_n_next = find_next_string_line(l_n, lines)
                line_concat = "\n".join(lines[l_n: l_n_next])
                self.asmstrs.append(AsmString(line_concat))
                l_n = l_n_next
            else:
                Log.warn(f"_read_strings, else hit. l_n {l_n} line {line}, should occur only once")
                l_n += 1

    def _debug_str(self) -> str:
        out = f"DisFile: {self.source_binary_name} language {self.language} \
literals({len(self.literals)}) records({len(self.records)}) methods({self.method_len()}) asmstrs({len(self.asmstrs)}) \
module_info({len(self.module_info)}) _debug {self._debug}"
        return out

    def _debug_vstr(self) -> str:
        out = self._debug_str() + "\n"
        for address, lit in self.literals.items():
            out += f">> {lit._debug_vstr()}\n"
        for module_name, rec in self.records.items():
            out += f">> {rec._debug_vstr()}\n"
        for module_name, name_meth_d in self.methods.items():
            for method_name, meth in name_meth_d.items():
                out += f">> {meth._debug_vstr()}\n"
        for asmstr in self.asmstrs:
            out += f">> {asmstr._debug_vstr()}\n"
        for module_name, mi in self.module_info.items():
            out += f">> {mi._debug_vstr()}\n"
        return out

    @property
    def dis_name(self) -> str:
        return self.source_binary_name + ".dis"

    def get_abc_name(self) -> str:
        return self.source_binary_name

    def method_len(self) -> int:
        meth_cnt = 0
        for _, d in self.methods.items():
            meth_cnt += len(d)
        return meth_cnt

    def get_literal_by_addr(self, addr: int) -> Union[AsmLiteral, None]:
        if (addr in self.literals):
            return self.literals[addr]
        return None

    def get_record_by_module_name(self, module_name: str) -> AsmRecord:
        if (module_name in self.records):
            return self.records[module_name]
        return None

    def get_external_module_name(self, module_name: str, idx: int) -> Union[str, None]:
        hit_rec = None
        if (len(module_name) > 0):
            hit_rec = self.get_record_by_module_name(module_name)
            if (hit_rec is not None and "moduleRecordIdx" in hit_rec.fields):
                ty, addr = hit_rec.fields["moduleRecordIdx"]
                lit = self.get_literal_by_addr(addr)
                if (lit is not None and idx >= 0 and idx < len(lit.module_tags)
                        and isinstance(lit.module_tags[idx], dict)
                        and "module_request" in lit.module_tags[idx]):
                    return lit.module_tags[idx]["module_request"]
        Log.warn(f"get_external_module_name failed, module_name {module_name} hit_rec {hit_rec}", True)
        return None

    def _ini_modulevar_local(self, module_name: str, lit: AsmLiteral) -> bool:
        if (module_name not in self.module_info):
            return False
        idx = 0
        for d in lit.module_tags:
            if (isinstance(d, dict) and "ModuleTag" in d and d["ModuleTag"] == "LOCAL_EXPORT"):
                if ("local_name" in d):
                    if ("export_name" in d and d["local_name"] != d["export_name"]):
                        Log.warn(f"local_module!=export_name {d['local_name']} != {d['export_name']} {module_name}")
                    self.module_info[module_name].set_var_local(idx, d["local_name"])
                    idx += 1
        return True

    def get_local_module_name(self, module_name: str, idx: int) -> Union[str, None]:
        if (module_name in self.module_info):
            return self.module_info[module_name].get_var_local(idx)
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

    def _module_obj_name_preprocess(self, obj_name: str) -> str:
        if (obj_name.startswith("__")):
            return obj_name[2:]
        return obj_name

    def new_module_obj(self, module_name: str, obj_name: str, value=None) -> bool:
        obj_name = self._module_obj_name_preprocess(obj_name)
        if (module_name not in self.module_info):
            return False
        self.module_info[module_name].set_obj(obj_name, value)
        return True

    def set_module_obj(self, module_name: str, obj_name: str, value):
        self.new_module_obj(module_name, obj_name, value)

    def get_module_obj_values(self, module_name: str, obj_name: str) -> Union[set, None]:
        obj_name = self._module_obj_name_preprocess(obj_name)
        if (module_name in self.module_info):
            return self.module_info[module_name].get_obj(obj_name)
        return None

    def get_meth(self, module_name: str = None, method_name: str = None,
                 module_method_name: str = None) -> Union[AsmMethod, None]:
        if (module_method_name is None):
            if (module_name in self.methods and method_name in self.methods[module_name]):
                return self.methods[module_name][method_name]
        elif (module_method_name is not None and len(module_method_name) > 0):
            module_name, method_name = utils.split_to_module_method_name(module_method_name)
            return self.get_meth(module_name, method_name)
        return None

    def _func_main_0_class_construct(self, module_name: str):
        print(f"_func_main_0_class_construct module_name {module_name}")
        func_main_0 = "func_main_0"
        meth = self.get_meth(module_name, func_main_0)
        # TODO: special logic for main_0

    def _set_HomeObject(self, module_name: str, module_method_name: str) -> bool:
        if (module_name in self.module_info):
            self.module_info[module_name].set_HomeObject_method(module_method_name)
            return True
        else:
            Log.error(f"_set_HomeObject failed, module_name {module_name} not in self.module_info")
            return False

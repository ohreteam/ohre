from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class AsmLiteral(DebugBase):
    # fields in Class
    def __init__(self, lines: List[str]):
        first_line_parts = lines[0].strip().split(" ")
        assert first_line_parts[0].isdigit()
        self.id = int(first_line_parts[0])
        self.address = int(first_line_parts[1], 16)
        self.module_request_array: Dict = None
        self.module_tags: List[Dict] = None
        if (len(lines) == 1):
            print(f"AsmLiteral todo: single line, processer is todo")  # TODO: normal situation
        else:
            self._process_module_request_array(lines)

    def _process_module_request_array(self, lines: List[str]):
        s_idx = lines[0].find("{")
        e_idx = lines[0].find("[")
        module_tag_cnt = lines[0][s_idx + 1:e_idx].strip()
        assert module_tag_cnt.isdigit()
        module_tag_cnt = int(module_tag_cnt)
        # module_request_array
        line_all = ""
        for s in lines:
            line_all += s
        module_request_array_start = line_all.find("MODULE_REQUEST_ARRAY: {") + len("MODULE_REQUEST_ARRAY: {")
        module_request_array_end = line_all.find("};", module_request_array_start)
        assert module_request_array_start > 0 and module_request_array_end > 0
        module_request_array = line_all[module_request_array_start:module_request_array_end].strip()
        module_request_dict = {}
        if len(module_request_array):
            module_requests = module_request_array.split(",")
            for module_request in module_requests:
                key, value = utils.find_single_kv(module_request, ":")
                if (key is not None and value is not None and key.isdigit()):
                    key = int(key)
                    module_request_dict[key] = value
        self.module_request_array = module_request_dict
        # module_tags
        module_tags_str_all = line_all[module_request_array_end:].strip()
        module_tags_l = list()
        if len(module_tags_str_all):
            module_tags_str_all = module_tags_str_all.split(";")
            for module_tag_line in module_tags_str_all:
                kv_s = module_tag_line.split(",")
                d = dict()
                for kv in kv_s:
                    key, value = utils.find_single_kv(kv.strip(), ":")
                    if (key is not None and value is not None):
                        d[key] = value
                if (len(d)):
                    module_tags_l.append(d)
        self.module_tags = module_tags_l

    def _debug_str(self) -> str:
        out = f"AsmLiteral: {self.id} {hex(self.address)}"
        if (self.module_request_array is not None):
            out += f" module_request_array({len(self.module_request_array)})"
        if (self.module_tags is not None):
            out += f" module_tags({len(self.module_tags)})"
        return out

    def _debug_vstr(self) -> str:
        out = f"AsmLiteral: {self.id} {hex(self.address)}"
        if (self.module_request_array is not None):
            out += f" module_request_array({len(self.module_request_array)}) {self.module_request_array}"
        if (self.module_tags is not None):
            out += f" module_tags({len(self.module_tags)}) {self.module_tags}"
        return out

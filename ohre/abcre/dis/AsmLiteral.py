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
        try:
            for s in lines:
                idx = s.find("MODULE_REQUEST_ARRAY: {")
                if (idx >= 0):
                    self._process_module_request_array(lines)
                    return
            self._process_normal_literal(lines)
        except Exception as e:
            Log.error(f"init ERROR in AsmLiteral, e {e}, lines {lines}")

    def _process_normal_literal(self, lines: List[str]):
        literal_content = ' '.join(lines)
        s_idx = literal_content.find("{") + 1
        e_idx = literal_content.find("[")
        element_amount_str = literal_content[s_idx:e_idx].strip()
        assert element_amount_str.isdigit(), f"Expected a digit for element amount, got {element_amount_str}"
        element_amount = int(element_amount_str)

        s_idx = literal_content.find("[") + 1
        e_idx = literal_content.find("]")
        element_content = literal_content[s_idx:e_idx]
        modified_content = element_content
        s_cnt = 0
        change_flag = 0
        for i in element_content:
            if i == '"':
                change_flag = abs(1-change_flag)
                s_cnt += 1
            elif i == ',' and change_flag == 1:
                modified_content = modified_content[:s_cnt] + \
                    '<comma>'+modified_content[s_cnt+1:]
                s_cnt += 7
            else:
                s_cnt += 1

        array_split_list = [x.strip() for x in modified_content.strip().split(',') if len(x) > 0]

        method_dict = {}
        if 'method' in element_content and 'method_affiliate' in element_content:
            cnt = 0
            while cnt < len(array_split_list):
                if 'string' in array_split_list[cnt]:
                    method_string = array_split_list[cnt].split(':')[
                        1].strip()[1:-1]
                    method_name = array_split_list[cnt+1].split(':')[1].strip()
                    method_aff = array_split_list[cnt+2].split(':')[1].strip()
                    method_dict[method_string] = {
                        'method': method_name, 'method_affiliate': method_aff}
                    cnt += 3
                else:
                    cnt += 1
            method_amount = array_split_list[-1].split(':')[1]
            method_dict["method_amount"] = method_amount
        else:
            cnt = 0
            array_len = len(array_split_list)
            if element_amount % 2 == 1:
                array_len -= 1
            while cnt < array_len:
                variable_string = array_split_list[cnt].split(':')[1].strip()
                if '"' in variable_string:
                    variable_string = variable_string.replace('"', '')
                variable_value = array_split_list[cnt+1]
                if 'null_value' in variable_value:
                    variable_value = 'null_value'
                else:
                    variable_value = variable_value.split(":")[1].strip()
                    if '"' in variable_value:
                        variable_value = variable_value.replace('"', '').replace('<comma>',',')
                cnt += 2
                method_dict[variable_string] = variable_value
            if element_amount % 2 == 1:
                variable_string = array_split_list[cnt].split(':')[1].strip()
                if '"' in variable_string:
                    variable_string = variable_string.replace('"', '')
                method_dict[variable_string] = ''
        self.module_tags = [method_dict]

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
                    key, value = utils.find_single_kv(kv, ":")
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

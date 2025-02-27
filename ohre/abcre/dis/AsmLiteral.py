import re
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
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
        literal_content = " ".join(lines)
        s_idx = literal_content.find("{") + 1
        e_idx = literal_content.find("[")
        element_amount_str = literal_content[s_idx:e_idx].strip()
        assert element_amount_str.isdigit(), f"Expected a digit for element amount, got {element_amount_str}"
        ele_cnt = int(element_amount_str)

        s_idx = literal_content.find("[") + 1
        e_idx = literal_content.find("]")
        element_content = literal_content[s_idx:e_idx]
        modified_content = element_content
        s_cnt = 0
        change_flag = 0
        element_content = element_content.replace('""""', "")
        element_content = element_content.replace('"""', "")
        for i in element_content:
            if (i == "\""):
                change_flag = abs(1 - change_flag)
                s_cnt += 1
            elif (i == "," and change_flag == 1):
                modified_content = modified_content[:s_cnt] + "<comma>" + modified_content[s_cnt + 1:]
                s_cnt += 7
            else:
                s_cnt += 1

        array_split_list = [x.strip() for x in modified_content.strip().split(",") if len(x) > 0]

        method_dict = {}
        if ("method" in element_content and "method_affiliate" in element_content):
            cnt = 0
            while cnt < len(array_split_list):
                if "string" in array_split_list[cnt] and "method" in array_split_list[cnt + 1]:
                    method_string = array_split_list[cnt].split(":")[
                        1].strip()[1:-1]
                    method_name = array_split_list[cnt + 1].split(":")[1].strip()
                    method_aff = array_split_list[cnt + 2].split(":")[1].strip()
                    method_dict[method_string] = {"method": method_name, "method_affiliate": method_aff}
                    cnt += 3
                elif ("string" in array_split_list[cnt] and "method" not in array_split_list[cnt + 1]):
                    var_str = array_split_list[cnt].split(":")[1].replace("\"", "").strip()
                    variable_value = array_split_list[cnt + 1].split(":")[1].replace("\"", "").strip()
                    if ("null_value" in array_split_list[cnt + 1]):
                        variable_value = "null_value"
                    method_dict[var_str] = variable_value
                    cnt += 2
                else:
                    cnt += 1
            method_amount = array_split_list[-1].split(":")[1]
            method_dict["method_amount"] = method_amount
        else:
            cnt = 0
            array_len = len(array_split_list)
            if (ele_cnt % 2 == 1):
                array_len -= 1
            while (cnt < array_len):
                var_str = array_split_list[cnt].split(":")[1].strip().replace("\"", "")
                if (len(var_str) == 0):
                    cnt += 2
                    continue
                variable_value = array_split_list[cnt + 1]
                if ("null_value" in variable_value):
                    variable_value = "null_value"
                else:
                    variable_value = variable_value.split(":")[1].strip()
                    if "\"" in variable_value:
                        variable_value = variable_value.replace("\"", "").replace("<comma>", ",")
                cnt += 2
                method_dict[var_str] = variable_value
            if (ele_cnt % 2 == 1):
                var_str = array_split_list[cnt].split(":")[1].strip()
                if ("\"" in var_str):
                    var_str = var_str.replace("\"", "")
                method_dict[var_str] = ""
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

    def _lit_split_by_comma(s: str) -> List[str]:
        modified_content = s
        s_cnt = 0
        change_flag = 0
        for i in s:
            if i == "\"":
                change_flag = abs(1 - change_flag)
                s_cnt += 1
            elif i == "," and change_flag == 1:
                modified_content = modified_content[:s_cnt] + "<comma>" + modified_content[s_cnt + 1:]
                s_cnt += 7
            else:
                s_cnt += 1

        array_split_list = [x.strip() for x in modified_content.strip().split(",") if len(x) > 0]
        for i in range(len(array_split_list)):
            array_split_list[i] = array_split_list[i].replace("<comma>", ",")
        return array_split_list

    @classmethod
    def lit_get_array(cls, in_s: str) -> List[AsmArg]:
        ele_cnt, in_s = lit_preprocess_and_get_ele_cnt(in_s)
        if (ele_cnt == -1):
            return list()
        matches = lit_get_matches(in_s, ele_cnt)

        ret: List[AsmArg] = list()
        for i in range(len(matches)):
            if (i != len(matches) - 1):
                end_idx = matches[i + 1]["start"]
            else:
                end_idx = len(in_s)
            value = utils.strip_sted_str(in_s[matches[i]["end"]: end_idx].strip(), None, ",")
            value = utils.strip_sted_str(value, "\"", "\"")
            ty = utils.strip_sted_str(matches[i]["text"], None, ":").strip()
            arg = AsmArg.build_with_type(ty, value)
            ret.append(arg)
            if (arg.type == AsmTypes.UNKNOWN):
                Log.error(f"lit_get_array got UNKNOWN: {i} {ty} : {value} arg {arg}")
        if (len(ret) != ele_cnt):
            Log.error(f"lit_get_array ret-unmatched: {len(ret)} {ret} ele_cnt {ele_cnt} // {in_s}")
        return ret

    @classmethod
    def lit_get_key_value(cls, in_s: str) -> Dict[str, AsmArg]:
        ele_cnt, in_s = lit_preprocess_and_get_ele_cnt(in_s)
        if (ele_cnt == -1):
            return dict()
        matches = lit_get_matches(in_s, ele_cnt)

        if (len(matches) != ele_cnt):
            Log.error(f"lit_get_key_value-unmatch {ele_cnt} matches {len(matches)} {matches}// {in_s}")
            return None

        def process_a_kv(i: int, matches: List[Dict[str, Any]], in_s: str) -> Tuple[int, str, AsmArg]:
            if (i + 1 != len(matches) - 1):
                end_idx = matches[i + 2]["start"]
            else:
                end_idx = len(in_s)
            name = utils.strip_sted_str(in_s[matches[i]["end"]: matches[i + 1]["start"]].strip(), None, ",")
            name = utils.strip_sted_str(name, "\"", "\"")
            value_v = utils.strip_sted_str(in_s[matches[i + 1]["end"]: end_idx].strip(), None, ",")
            value_v = utils.strip_sted_str(value_v, "\"", "\"")
            value_ty = utils.strip_sted_str(matches[i + 1]["text"], None, ":").strip()
            if (name == "\n"):
                name = "\\n"
            return i + 2, name, AsmArg.build_with_type(value_ty, value_v)

        ret: Dict[str, AsmArg] = dict()
        i = 0
        while (i < ele_cnt):
            if (i + 2 < ele_cnt and "method_affiliate" in matches[i + 2]["text"]):
                i, name, asm_arg = process_a_method_lit(i, matches, in_s)
                ret[name] = asm_arg
            elif (i + 1 < ele_cnt):
                i, name, asm_arg = process_a_kv(i, matches, in_s)
                if (name == ""):
                    name = "None"
                ret[name] = asm_arg
            else:
                Log.error(f"lit_get_key_value else hit {ele_cnt} matches {len(matches)} {matches} // {in_s}")
        if (len(ret) != ele_cnt / 2 and len(ret) != ele_cnt / 3):
            Log.warn(f"lit_get_key_value: {len(ret)} {ret} ele_cnt {ele_cnt} // {in_s}")
        return ret

    @classmethod
    def lit_get_class_method(cls, in_s: str) -> Union[Dict[str, AsmArg], None]:
        ele_cnt, in_s = lit_preprocess_and_get_ele_cnt(in_s)
        if (ele_cnt % 3 != 1):
            Log.error(f"lit_get_class_method: ele_cnt {ele_cnt} % 3 != 1 in_s {in_s}")
        matches = lit_get_matches(in_s, ele_cnt)
        ret: Dict[str, AsmArg] = dict()
        for i in range(0, ele_cnt, 3):
            if (i + 2 >= ele_cnt):
                continue
            if ("method_affiliate" in matches[i + 2]["text"]):
                i, name, asm_arg = process_a_method_lit(i, matches, in_s)
                ret[name] = asm_arg
        if (len(matches)):
            method_cnt = in_s[matches[-1]["end"]:]
            method_cnt = utils.strip_sted_str(method_cnt.strip(), ",", ",")
            if (method_cnt.isdigit()):
                method_cnt = int(method_cnt)
                if (method_cnt != len(ret)):
                    Log.error(f"lit_get_class_method: method_cnt {method_cnt} != len(ret) {len(ret)}")
            else:
                Log.error(f"lit_get_class_method: method_cnt is not digit, method_cnt {method_cnt}")
        return ret


lit_fixed_patterns = [" null_value:", " u1:", " string:", " method_affiliate:", " f64:", " i32:", " method:"]


def lit_preprocess_and_get_ele_cnt(in_s: str) -> Tuple[int, str]:
    in_s = utils.strip_sted_str(in_s.strip(), "{", "}").strip()
    e_idx = in_s.find("[")
    ele_cnt = in_s[0:e_idx].strip()
    if (not ele_cnt.isdigit()):
        Log.error(f"Expected a digit for element amount, got {ele_cnt}")
        return -1, in_s
    ele_cnt = int(ele_cnt)
    in_s = utils.strip_sted_str(in_s[e_idx:], "[", "]")
    return ele_cnt, in_s


def lit_get_matches(in_s: str, ele_cnt: int) -> List[Dict[str, Any]]:
    global lit_fixed_patterns
    # pattern = r" [a-zA-Z0-9_]+:" # NOTE: if need to support more key, used this pattern
    pattern = r"(" + "|".join(re.escape(p) for p in lit_fixed_patterns) + ")"
    matches: List[Dict[str, Any]] = list()
    for match in re.finditer(pattern, in_s):
        matches.append({"text": match.group(), "start": match.start(), "end": match.end()})

    if (len(matches) != ele_cnt):
        Log.error(f"lit_get_matches unmatched: matches {matches} != {ele_cnt} // {in_s}")
    if (len(matches) == 0):
        Log.error(f"lit_get_matches matches=0: matches {matches} != {ele_cnt} // {in_s}")
    return matches


def process_a_method_lit(i: int, matches: List[Dict[str, Any]], in_s: str) -> Tuple[int, str, AsmArg]:
    if (i + 2 != len(matches) - 1):
        end_idx = matches[i + 3]["start"]
    else:
        end_idx = len(in_s)
    name = utils.strip_sted_str(in_s[matches[i]["end"]: matches[i + 1]["start"]].strip(), None, ",")
    name = utils.strip_sted_str(name, "\"", "\"")
    method = utils.strip_sted_str(in_s[matches[i + 1]["end"]: matches[i + 2]["start"]].strip(), None, ",")
    method_affiliate = utils.strip_sted_str(in_s[matches[i + 2]["end"]: end_idx].strip(), None, ",")
    method_affiliate = int(method_affiliate)
    return i + 3, name, AsmArg(AsmTypes.METHOD_OBJ, name=method, paras_len=method_affiliate + 3)

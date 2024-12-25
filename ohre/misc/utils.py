from typing import Any, Dict, Iterable, List, Tuple, Union
import yaml
import copy

def is_uppercase_or_underscore(s: str):
    return all(c.isupper() or c.isdigit() or c == "_" for c in s)


def find_idx_in_list(l, ele):
    for i in range(len(l)):
        if (l[i] == ele):
            return i
    return -1


def is_right_and_match_stack_top(stack_l: list, pair_left_char_l: list, pair_right_char_l: list, c) -> bool:
    if (len(stack_l) == 0):
        return False
    l_idx = find_idx_in_list(pair_left_char_l, stack_l[-1])
    assert l_idx >= 0
    r_idx = find_idx_in_list(pair_right_char_l, c)
    if (r_idx == l_idx):
        return True
    return False


def is_left(pair_left_char_l, c):
    if (find_idx_in_list(pair_left_char_l, c) >= 0):
        return True
    return False


def find_next_delimiter_single_line(line: str, start_idx: int = 0, delimiter: str = ",",
                                    pair_left_char_l: List = ["\"", "(", "[", "{"],
                                    pair_right_char_l: List = ["\"", ")", "]", "}"]):
    # e.g. to get coressponding idx of '}' in such single line: {("[1(abc)*]11")}
    stack_l = list()
    for idx in range(start_idx, len(line)):
        if (is_right_and_match_stack_top(stack_l, pair_left_char_l, pair_right_char_l, line[idx])):
            stack_l.pop()
        elif (is_left(pair_left_char_l, line[idx])):
            stack_l.append(line[idx])
        elif (line.find(delimiter, idx) == idx and len(stack_l) == 0):
            return idx
    return len(line)

def find_matching_symbols_multi_line(lines: List[str], start_char: str,
                                     pair_left_char_l: List = ["\"", "(", "[", "{"],
                                     pair_right_char_l: List = ["\"", ")", "]", "}"]) -> Tuple[int, int]:
    # find the corressponding right char of `start_char`, return the line idx and idx in that line
    # attention: start_char should in pair_left_char_l
    stack_l = list()
    assert isinstance(start_char, str) and len(start_char) == 1
    start_char_hit = False
    for l_idx in range(len(lines)):
        for n_idx in range(len(lines[l_idx])):
            if (is_right_and_match_stack_top(stack_l, pair_left_char_l, pair_right_char_l, lines[l_idx][n_idx])):
                stack_l.pop()
                if (start_char_hit and len(stack_l) == 0):
                    return l_idx, n_idx
            elif (lines[l_idx][n_idx] == start_char):
                stack_l.append(lines[l_idx][n_idx])
                start_char_hit = True
            elif (is_left(pair_left_char_l, lines[l_idx][n_idx])):
                stack_l.append(lines[l_idx][n_idx])
    return None, None

def read_dict_from_yaml_file(f_name: str) -> dict:
    ret = None
    with open(f_name) as stream:
        try:
            ret = yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print(f"read yaml failed, e:{e}")
    return ret

def find_single_kv(s: str, delimiter: str = ":") -> Tuple[Union[str, None], Union[str, None]]:
    # "1 : @ohos:hilog" to ("1", "@ohos:hilog") # only match the first delimiter
    s = s.strip()
    idx = s.find(delimiter)
    if (idx > 0):
        key = s[:idx].strip()
        value = s[idx + len(delimiter):].strip()
        return key, value
    else:
        return None, None

def hexstr(value) -> str:
    ret = ""
    if isinstance(value, Iterable):
        for i in range(len(value)):
            if (i != len(value) - 1):
                ret += f"{hexstr(value[i])},"
            else:
                ret += f"{hexstr(value[i])}"
    elif (isinstance(value, int)):
        ret = f"{hex(value)}"
    else:
        ret = f"{value}"
    return ret


if __name__ == "__main__":
    temp = """newlexenvwithname 0x2, { 5 [ i32:2, string:"4newTarget", i32:0, string:"this", i32:1, ]}"""
    idx = find_next_delimiter_single_line(temp, 17)
    print(f"idx {idx} {temp[17: idx]}")
    idx = find_next_delimiter_single_line(temp, 22)
    print(f"idx {idx} {temp[22: idx]}")

    temp = [
        "12 0x15f5 { 3 [", "MODULE_REQUEST_ARRAY: {", "    0 : @ohos:app.ability.UIAbility,", "    1 : @ohos:hilog,",
        "};",
        "ModuleTag: REGULAR_IMPORT, local_name: UIAbility, import_name: default, module_request: @ohos:app.ability.UIAbility;",
        "ModuleTag: REGULAR_IMPORT, local_name: hilog, import_name: default, module_request: @ohos:hilog;",
        "ModuleTag: LOCAL_EXPORT, local_name: EntryAbility, export_name: default;", "]}"]
    l_idx, n_idx = find_matching_symbols_multi_line(temp, "{")
    print(f"l_idx {l_idx} n_idx {n_idx}")

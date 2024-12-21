from typing import Any, Dict, Iterable, List, Tuple
import yaml


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


def find_next_delimiter(line: str, start_idx: int = 0, delimiter: str = ",",
                        pair_left_char_l: List = ["\"", "(", "[", "{"],
                        pair_right_char_l: List = ["\"", ")", "]", "}"]):
    stack_l = list()
    for idx in range(start_idx, len(line)):
        if (is_right_and_match_stack_top(stack_l, pair_left_char_l, pair_right_char_l, line[idx])):
            stack_l.pop()
        elif (is_left(pair_left_char_l, line[idx])):
            stack_l.append(line[idx])
        elif (line.find(delimiter, idx) == idx and len(stack_l) == 0):
            return idx
    return len(line)


def read_dict_from_yaml_file(f_name: str) -> dict:
    ret = None
    with open(f_name) as stream:
        try:
            ret = yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print(f"read yaml failed, e:{e}")
    return ret


def hexstr(value) -> str:
    ret = ""
    if isinstance(value, Iterable):
        for i in range(len(value)):
            if (i != len(value) - 1):
                ret += f"{hex(value[i])},"
            else:
                ret += f"{hex(value[i])}"
    elif (isinstance(value, int)):
        ret = f"{hex(value)}"
    else:
        ret = f"unsupported_value_type! value:{value}"
    return ret


if __name__ == "__main__":
    temp = """newlexenvwithname 0x2, { 5 [ i32:2, string:"4newTarget", i32:0, string:"this", i32:1, ]}"""
    idx = find_next_delimiter(temp, 17)
    print(f"idx {idx} {temp[17: idx]}")
    idx = find_next_delimiter(temp, 22)
    print(f"idx {idx} {temp[22: idx]}")

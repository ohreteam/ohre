from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class AsmArg(DebugBase):
    def __init__(self, arg_type: AsmTypes = AsmTypes.UNKNOWN,
                 name: str = "", value=None, ref_base=None, paras_len: int = None):
        self.type = arg_type
        # name: e.g. for v0, type is VAR, name is v0(stored without truncating the prefix v)
        self.name: str = name
        # value: may be set in the subsequent analysis
        # type is ARRAY: value is list[AsmArg]
        # type is OBJECT: value is list[AsmArg]: AsmArg(name:key, value:any value)
        self.value = value
        self.ref_base = ref_base  # AsmArg
        self.paras_len: Union[int, None] = paras_len  # for method object, store paras len here
        if (self.is_value_valid() == False):
            Log.error(f"AsmArg value is NOT valid, type {self.type_str} value {type(value)} {value}")

    @property
    def len(self):
        if (len(self.name) > 0):
            return len(self.name)
        return len(self.type)

    @property
    def type_str(self) -> str:
        return AsmTypes.get_code_name(self.type)

    def __len__(self) -> int:
        return self.len

    def __eq__(self, rhs):
        if isinstance(rhs, AsmArg):
            if (self.type == rhs.type and self.name == rhs.name):
                if (self.ref_base == rhs.ref_base and self.value == rhs.value and self.paras_len == rhs.paras_len):
                    return True
                else:
                    return False
            else:
                return False
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        ref_base = self.ref_base if self.ref_base is not None else 'None'
        return hash((self.type, self.name, ref_base))

    def __repr__(self):
        return f"Arg({self._debug_str()})"

    def obj_has_key(self, key) -> bool:
        # if self is OBJECT and key exists in self.value, return True
        if (not isinstance(self.value, Iterable)):
            return False
        key_name_str: str = ""
        if (isinstance(key, AsmArg)):
            key_name_str = key.name
        elif (isinstance(key, str)):
            key_name_str = key
        else:
            Log.error(f"ERROR! obj_has_key key {type(key)} {key}")
        for arg in self.value:
            if (key_name_str == arg.name):
                return True
        return False

    def set_object_key_value(self, key: str, value: str, create=False):
        if (self.type != AsmTypes.OBJECT):
            return False
        for arg in self.value:
            if (key == arg.name):
                arg.value = value
                return True
        return False

    def set_ref(self, ref_ed_arg):
        self.ref_base = ref_ed_arg

    def is_has_ref(self) -> bool:
        if (self.ref_base is not None):
            return True
        else:
            return False

    def is_no_ref(self) -> bool:
        return not self.is_has_ref()

    @classmethod
    def build_arg(cls, s: str):  # return VAR v0 v1... or ARG a0 a1...
        assert isinstance(s, str) and len(s) > 0
        if (s.startswith("v")):
            return AsmArg(AsmTypes.VAR, s)
        if (s.startswith("a")):
            if (s == "a0"):
                return cls.build_FunctionObject()
            elif (s == "a1"):
                return cls.build_NewTarget()
            elif (s == "a2"):
                return cls.build_this()
            return AsmArg(AsmTypes.ARG, s)
        if (s.startswith("tmp")):
            return AsmArg(AsmTypes.VAR, s)
        Log.error(f"build_arg failed: s={s}")

    @classmethod
    def build_acc(cls):  # return AsmArg(AsmTypes.ACC)
        return cls.ACC()

    @classmethod
    def ACC(cls):  # return AsmArg(AsmTypes.ACC)
        return AsmArg(AsmTypes.ACC)

    @classmethod
    def build_arr(cls, args: List, name: str = ""):  # element of args should be AsmArg
        return AsmArg(AsmTypes.ARRAY, name=name, value=list(args))

    @classmethod
    def build_object(cls, in_kv: Dict = None, name: str = "", ref_base=None):  # element of args should be AsmArg
        obj_value_l = list()
        if (isinstance(in_kv, Iterable)):
            for k, v in in_kv.items():
                if (isinstance(v, int)):
                    obj_value_l.append(AsmArg(AsmTypes.IMM, name=k, value=v))
                elif (isinstance(v, float)):
                    obj_value_l.append(AsmArg(AsmTypes.IMM, name=k, value=v))
                elif (isinstance(v, str)):
                    obj_value_l.append(AsmArg(AsmTypes.STR, name=k, value=v))
                elif (v is None):
                    obj_value_l.append(AsmArg(AsmTypes.UNDEFINED, name=k, value=None))
                else:
                    Log.error(f"ERROR! build_object k {k} {type(k)} v {v} {type(v)} name {name}")
        if (len(obj_value_l) == 0):
            obj_value_l = None
        return AsmArg(AsmTypes.OBJECT, name=name, value=obj_value_l, ref_base=ref_base)

    @classmethod
    def build_FunctionObject(cls):
        # FunctionObject always stored at a0
        return AsmArg(AsmTypes.ARG, name="FunctionObject")

    @classmethod
    def build_NewTarget(cls):
        # NewTarget always stored at a1
        return AsmArg(AsmTypes.ARG, name="NewTarget")

    @classmethod
    def build_this(cls):
        # this always stored at a2
        return AsmArg(AsmTypes.ARG, name="this")

    def build_next_arg(self):  # arg is AsmArg
        # if self is v5, return v6; if self is a0, return a1; just num_part+=1
        num_part: str = self.name[1:]
        assert num_part.isdigit()
        num = int(num_part)
        num += 1
        return AsmArg(self.type, f"{self.name[0]}{num}")

    def is_value_valid(self) -> bool:
        if (self.value is None):
            return True
        if (self.type == AsmTypes.IMM):
            if (isinstance(self.value, int) or isinstance(self.value, float)):
                return True
            return False
        if (self.type == AsmTypes.STR or self.type == AsmTypes.LABEL):
            if (isinstance(self.value, str)):
                return True
            return False
        if (self.type == AsmTypes.METHOD_OBJ):
            if (isinstance(self.value, str)):
                return True
            return False
        if (self.type == AsmTypes.OBJECT):
            if (isinstance(self.value, Iterable)):
                return True
            return False
        if (self.type == AsmTypes.ARRAY):
            if (isinstance(self.value, list)):
                return True
            return False
        if (self.type == AsmTypes.NULL or self.type == AsmTypes.INF or self.type == AsmTypes.NAN
                or self.type == AsmTypes.UNDEFINED or self.type == AsmTypes.HOLE):
            return False
        Log.error(f"is_value_valid NOT supported logic type {self.type_str} value {type(self.value)} {self.value}")
        return True

    def is_acc(self) -> bool:
        if (self.type == AsmTypes.ACC):
            return True
        return False

    def is_imm(self) -> bool:
        if (self.type == AsmTypes.IMM):
            return True
        return False

    def is_field(self) -> bool:
        if (self.type == AsmTypes.FIELD):
            return True
        return False

    def is_unknown(self) -> bool:
        if (self.type == AsmTypes.UNKNOWN):
            return True
        return False

    def is_temp_var_like(self) -> bool:
        if ((self.type == AsmTypes.VAR or self.type == AsmTypes.ACC) and self.is_no_ref()):
            return True
        return False

    def get_all_args_recursively(self, include_self: bool = True) -> List:
        out = list()
        if (include_self):
            out.append(self)
        if (isinstance(self.ref_base, AsmArg)):
            out.append(self.ref_base)
        if (self.value is not None and isinstance(self.value, Iterable)):  # if type is ARRAY
            for v in self.value:
                if (isinstance(v, AsmArg)):
                    out.append(v)
        return out

    def _common_error_check(self):
        if (self.type == AsmTypes.FIELD):
            if (self.ref_base is None or len(self.name) == 0):
                Log.error(f"[ArgCC] A filed without ref_base or name len==0: name {self.name} len {len(self.name)}")
        if (self.type == AsmTypes.MODULE):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A module without name: len {len(self.name)}")
        if (self.type == AsmTypes.METHOD):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A method without name: len {len(self.name)}")
        if (self.type == AsmTypes.LABEL):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A label without name: len {len(self.name)}")

    def _debug_str_obj(self, detail=False):
        out = ""
        if (self.ref_base is not None):
            out += f"{self.ref_base}->"
        if (detail):
            out += f"OBJ:{self.name}"
        else:
            out += f"{self.name}"
        if (isinstance(self.value, Iterable)):
            out += "{"
            for v_arg in self.value:
                out += f"{v_arg.name}:{v_arg.value}, "
            out += "}"
        elif (self.value is not None):
            out += "{" + self.value + "}"
        return out

    def _debug_str(self, print_ref: bool = True):
        self._common_error_check()
        out = ""
        if (self.type == AsmTypes.OBJECT):
            return self._debug_str_obj()
        if (self.type == AsmTypes.FIELD):
            if (print_ref and self.ref_base is not None):
                out += f"{self.ref_base}[{self.name}]"
            else:
                out += f"[field:{self.name}]"
        else:
            if (print_ref and self.ref_base is not None):
                out += f"{self.ref_base}->"
            out += f"{self.name}"
            if (len(self.name) == 0):
                out += f"{AsmTypes.get_code_name(self.type)}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.paras_len is not None):
            out += f"(paras_len={self.paras_len})"
        return out

    def _debug_vstr(self, print_ref: bool = True):
        self._common_error_check()
        out = ""
        if (self.type == AsmTypes.OBJECT):
            return self._debug_str_obj(detail=True)
        if (self.type == AsmTypes.FIELD):
            if (print_ref and self.ref_base is not None):
                out += f"{self.ref_base}[{AsmTypes.get_code_name(self.type)}-{self.name}]"
            else:
                out += f"[{AsmTypes.get_code_name(self.type)}-{self.name}]"
        else:
            if (print_ref and self.ref_base is not None):
                out += f"{self.ref_base}->"
            out += f"{AsmTypes.get_code_name(self.type)}-{self.name}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.paras_len is not None):
            out += f"(paras_len={self.paras_len})"
        return out

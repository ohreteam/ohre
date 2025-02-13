from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class AsmArg(DebugBase):
    def __init__(self, arg_type: AsmTypes = AsmTypes.UNKNOWN,
                 name="", value=None, ref_base=None, paras_len: int = None):
        self.type = arg_type
        # name: e.g. for v0, type is VAR, name is v0(stored without truncating the prefix v)
        self.name: Union[str, AsmArg] = name
        # value: may be set in the subsequent analysis
        # type is ARRAY: value is list[AsmArg]
        # type is OBJECT: value is dict str->AsmArg: key: str, value: AsmArg
        self.value: Union[int, float, str, List[AsmArg], Dict[str, AsmArg]] = value
        self.ref_base = ref_base  # AsmArg
        self.paras_len: Union[int, None] = paras_len  # for method object, store paras len here
        if (self.is_value_valid() == False):
            Log.error(f"AsmArg value is NOT valid, type {self.type_str} value {type(value)} {value}")

    @property
    def len(self) -> int:
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
        for name in self.value.keys():
            if (key_name_str == name):
                return True
        return False

    def set_object_key_value(self, key: str, value_arg, create=False) -> bool:
        # value_arg: a AsmArg
        if (not isinstance(value_arg, AsmArg)):
            return False
        if (self.type != AsmTypes.OBJECT):
            return False
        for name, arg in self.value.items():
            if (key == name):
                self.value[name] = value_arg
                return True
        if (create):
            self.value[name] = value_arg
            return True
        return False

    def set_ref(self, ref_ed_arg) -> bool:
        if (isinstance(ref_ed_arg, AsmArg)):
            self.ref_base = ref_ed_arg
            return True
        return False

    def has_ref(self) -> bool:
        if (self.ref_base is not None and isinstance(self.ref_base, AsmArg)):
            return True
        else:
            return False

    def is_no_ref(self) -> bool:
        return not self.has_ref()

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
    def build_acc(cls):
        return cls.ACC()

    @classmethod
    def ACC(cls):
        return AsmArg(AsmTypes.ACC)

    @classmethod
    def NULL(cls):
        return AsmArg(AsmTypes.NULL)

    @classmethod
    def build_arr(cls, args: List, name: str = ""):  # element of args should be AsmArg
        return AsmArg(AsmTypes.ARRAY, name=name, value=list(args))

    @classmethod
    def build_object(cls, in_kv: Dict = None, name: str = "", ref_base=None):
        obj_value_d: Dict[str, AsmArg] = dict()
        if (isinstance(in_kv, Iterable)):
            for k, v in in_kv.items():
                if (isinstance(v, int)):
                    obj_value_d[k] = AsmArg(AsmTypes.IMM, value=v)
                elif (isinstance(v, float)):
                    obj_value_d[k] = AsmArg(AsmTypes.IMM, value=v)
                elif (isinstance(v, str)):
                    obj_value_d[k] = AsmArg(AsmTypes.FIELD, value=v)
                elif (v is None):
                    obj_value_d[k] = AsmArg(AsmTypes.NULL)
                else:
                    obj_value_d[k] = AsmArg(AsmTypes.UNDEFINED, value=v)
                    Log.error(f"ERROR! build_object k {k} {type(k)} v {v} {type(v)} name {name}")
        if (len(obj_value_d) == 0):
            obj_value_d = None
        return AsmArg(AsmTypes.OBJECT, name=name, value=obj_value_d, ref_base=ref_base)

    @classmethod
    def build_object_with_asmarg(cls, in_kv: Dict = None, name: str = "", ref_base=None):
        # in_kv : k str, v AsmArg
        obj_value_d: Dict[str, AsmArg] = dict()
        if (isinstance(in_kv, Iterable)):
            for k, v in in_kv.items():
                if (isinstance(v, AsmArg)):
                    obj_value_d[k] = v
                else:
                    Log.error(f"ERROR! build_object_with_asmarg k {k} {type(k)} v {v} {type(v)} v is not AsmArg")
        if (len(obj_value_d) == 0):
            obj_value_d = None
        return AsmArg(AsmTypes.OBJECT, name=name, value=obj_value_d, ref_base=ref_base)

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

    @classmethod
    def build_with_type(cls, ty: str, value: str):
        if (AsmTypes.is_str(ty)):
            return AsmArg(AsmTypes.STR, value=value)
        if (AsmTypes.is_int(ty)):
            if (value.isdigit()):
                return AsmArg(AsmTypes.IMM, value=int(value))
        if (AsmTypes.is_float(ty)):
            if (utils.is_float(value)):
                return AsmArg(AsmTypes.IMM, value=float(value))
        if (ty == "null_value" and value == "0"):
            return AsmArg(AsmTypes.NULL)
        return AsmArg(AsmTypes.UNKNOWN, value=value)

    def is_arg_this(self) -> bool:
        if (self.type == AsmTypes.ARG and self.name == "this"):
            return True
        return False

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
            if (isinstance(self.value, dict)):
                return True
            return False
        if (self.type == AsmTypes.FIELD):
            if (isinstance(self.value, str) or isinstance(self.value, None)):
                return True
            return False
        if (self.type == AsmTypes.ARRAY):
            if (isinstance(self.value, list)):
                return True
            return False
        if (self.type == AsmTypes.NULL or self.type == AsmTypes.INF or self.type == AsmTypes.NAN
                or self.type == AsmTypes.UNDEFINED or self.type == AsmTypes.HOLE):
            return False
        if (self.type == AsmTypes.LEXENV):
            if (isinstance(self.value, int)):
                return True
            return False
        if (self.type != AsmTypes.UNKNOWN):
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

    def is_str(self) -> bool:
        if (self.type == AsmTypes.STR):
            return True
        return False

    def is_field(self) -> bool:
        if (self.type == AsmTypes.FIELD):
            return True
        return False

    def is_obj(self) -> bool:
        if (self.type == AsmTypes.OBJECT):
            return True
        return False

    def is_arg(self) -> bool:
        if (self.type == AsmTypes.ARG):
            return True
        return False

    def is_null(self) -> bool:
        if (self.type == AsmTypes.NULL):
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

    def is_specific_like(self) -> bool:
        if (self.type == AsmTypes.IMM or self.type == AsmTypes.STR):
            return True
        if (self.type == AsmTypes.TRUE or self.type == AsmTypes.FALSE):
            return True
        if (self.type == AsmTypes.ZERO or self.type == AsmTypes.NAN or self.type == AsmTypes.INF):
            return True
        return False

    def get_specific_value(self) -> Any:
        if (self.is_specific_like()):
            if (self.type == AsmTypes.IMM or self.type == AsmTypes.STR):
                return self.value
            if (self.type == AsmTypes.TRUE):
                return True
            if (self.type == AsmTypes.FALSE):
                return False
            if (self.type == AsmTypes.ZERO):
                return 0
            if (self.type == AsmTypes.NAN):
                return "NAN"
            if (self.type == AsmTypes.INF):
                return "INF"
        return None

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
            if (isinstance(self.name, str) and len(self.name) == 0):
                Log.error(f"[ArgCC] A filed name len==0: name {self.name} len {len(self.name)}")
        if (self.type == AsmTypes.MODULE):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A module without name: len {len(self.name)}")
        if (self.type == AsmTypes.METHOD):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A method without name: len {len(self.name)}")
        if (self.type == AsmTypes.LABEL):
            if (len(self.name) == 0):
                Log.error(f"[ArgCC] A label without name: len {len(self.name)}")
        if (self.type == AsmTypes.STR):
            if (len(self.name) != 0 or (not isinstance(self.value, str))):
                Log.error(f"[ArgCC] A str with name: {self.name} or value not str: {type(self.value)} {self.value}")

    def _debug_str_obj(self, detail: bool = False, print_ref: bool = True, visited=None) -> str:
        visited = visited or set()
        if id(self) in visited:
            return "[Circular]"
        visited.add(id(self))
        out = ""
        if (print_ref and self.ref_base is not None):
            out += f"{self.ref_base}."
        if (detail):
            out += f"OBJ:{self.name}"
        else:
            out += f"{self.name}"
        if (isinstance(self.value, dict)):
            out += "{"
            i = 0
            for name, arg in self.value.items():
                if (detail):
                    out += f"{name}: {arg._debug_vstr()}"
                else:
                    out += f"{name}: {arg}"
                if (i < len(self.value) - 1):
                    out += ", "
                i += 1
            out += "}"
        elif (self.value is not None):
            if (isinstance(self.value, str)):
                out += f"\"{self.value}\""
            else:
                out += "{" + self.value + "}"
        return out

    def _debug_str(self, print_ref: bool = True) -> str:
        self._common_error_check()

        if (self.type == AsmTypes.OBJECT):
            return self._debug_str_obj(detail=False, print_ref=print_ref)
        if (self.type == AsmTypes.STR and self.value is not None):
            return f"\"{self.value}\""

        out = ""
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

    def _debug_vstr(self, print_ref: bool = True) -> str:
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

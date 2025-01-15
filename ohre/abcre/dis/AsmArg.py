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
        self.value = value  # if type is ARRAY, value is AsmArg list
        self.ref_base = ref_base  # AsmArg
        self.paras_len: Union[int, None] = paras_len  # for method object, store paras len here

    @property
    def len(self):
        if (len(self.name) > 0):
            return len(self.name)
        return len(self.type)

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

    def is_value_valid(self) -> bool:  # TODO: for some types, value is not valid, judge it
        pass

    def is_acc(self) -> bool:
        if (self.type == AsmTypes.ACC):
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

    def _debug_str(self, print_ref: bool = True):
        self._common_error_check()
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

    def _debug_vstr(self, print_ref: bool = True):
        self._common_error_check()
        out = ""
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

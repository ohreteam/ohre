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
        self.value = value
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
                if (self.ref_base is None and rhs.ref_base is None):
                    return True
                elif (self.ref_base is None and rhs.ref_base is not None):
                    return False
                elif (self.ref_base is not None and rhs.ref_base is None):
                    return False
                else:  # both is NOT None
                    if (self.ref_base == rhs.ref_base):
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

    @classmethod
    def build_arg(cls, s: str):  # return VAR v0 v1... or ARG a0 a1...
        assert isinstance(s, str) and len(s) > 0
        if (s.startswith("v")):
            return AsmArg(AsmTypes.VAR, s)
        if (s.startswith("a")):
            return AsmArg(AsmTypes.ARG, s)
        if (s.startswith("tmp")):
            return AsmArg(AsmTypes.VAR, s)
        Log.error(f"build_arg failed: s={s}")

    @classmethod
    def build_arr(cls, args: List, name: str = ""):
        return AsmArg(AsmTypes.ARRAY, name=name, value=list(args))

    @classmethod
    def build_this(cls):
        # this always stored at a2
        return AsmArg(AsmTypes.ARG, name="a2")

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

    def _debug_str(self):
        out = ""
        if (len(self.name)):
            out += f"{self.name}"
        else:
            out = f"{AsmTypes.get_code_name(self.type)}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.ref_base is not None):
            out += f"//ref:{self.ref_base}"
        if (self.paras_len is not None):
            out += f"(paras_len={self.paras_len})"
        return out

    def _debug_vstr(self):
        out = f"{AsmTypes.get_code_name(self.type)}"
        if (len(self.name) > 0):
            out += f"-{self.name}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.ref_base is not None):
            out += f"//ref:{self.ref_base}"
        if (self.paras_len is not None):
            out += f"(paras_len={self.paras_len})"
        return out

from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class AsmArg(DebugBase):
    def __init__(self, arg_type: AsmTypes = AsmTypes.UNKNOWN,
                 name: str = "", value=None, obj_ref=None, paras_len: int = None):
        self.type = arg_type
        # name: e.g. for v0, type is VAR, name is v0(stored without truncating the prefix v)
        self.name: str = name
        # value: may be set in the subsequent analysis
        self.value = value
        self.obj_ref = obj_ref
        self.paras_len: Union[int, None] = paras_len  # for method object, store paras len here

    @property
    def len(self):
        return len(self.name)

    def __len__(self) -> int:
        return self.len

    @classmethod
    def build_arg(cls, s: str):  # return VAR v0 v1... or ARG a0 a1...
        assert isinstance(s, str) and len(s) > 0
        if (s.startswith("v")):
            return AsmArg(AsmTypes.VAR, s)
        if (s.startswith("a")):
            return AsmArg(AsmTypes.ARG, s)
        Log.error(f"build_arg failed: s={s}")

    def build_next_arg(self):  # arg is AsmArg
        # if self is v5, return v6; if self is a0, return a1; just num_part+=1
        num_part: str = self.name[1:]
        assert num_part.isdigit()
        num = int(num_part)
        num += 1
        return AsmArg(self.type, f"{self.name[0]}{num}")

    def is_value_valid(self) -> bool:  # TODO: for some types, value is not valid, judge it
        pass

    def _debug_str(self):
        out = f"{AsmTypes.get_code_name(self.type)}-{self.name}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.obj_ref is not None):
            out += f"//{self.obj_ref}"
        if (self.paras_len is not None):
            out += f"(paras_len={self.paras_len})"
        return out

    def _debug_vstr(self):
        out = f"{self._debug_str()}"
        return out

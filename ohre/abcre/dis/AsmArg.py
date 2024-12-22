from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.misc import Log, utils


class AsmArg:
    def __init__(self, arg_type: AsmTypes = AsmTypes.UNKNOWN, name="", value=None, obj_ref=None):
        self.type = arg_type
        # name: e.g. for v0, type is VAR, name is v0(stored without truncating the prefix v)
        self.name = name
        # value: may be set in the subsequent analysis
        self.value = value
        self.obj_ref = obj_ref

    def __str__(self):
        return self.debug_short()

    @classmethod
    def build_arg(cls, s: str):
        assert isinstance(s, str) and len(s) > 0
        if (s.startswith("v")):
            return AsmArg(AsmTypes.VAR, s)
        if (s.startswith("a")):
            return AsmArg(AsmTypes.ARG, s)
        Log.error(f"build_arg failed: s={s}")

    def is_value_valid(self) -> bool:  # TODO: for some types, value is not valid, judge it
        pass

    def debug_short(self):
        out = f"{AsmTypes.get_code_name(self.type)}-{self.name}"
        if (self.value is not None):
            out += f"({self.value})"
        if (self.obj_ref is not None):
            out += f"//{self.obj_ref}"
        return out

    def debug_deep(self):
        out = f"{self.debug_short()}"
        return out

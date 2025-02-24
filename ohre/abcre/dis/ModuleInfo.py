from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class ModuleInfo(DebugBase):
    def __init__(self, module_name: str):
        self.module_name = module_name
        # idx -> modulevar / a imported module name(str)
        self._var_local: Dict[int, Union[str, AsmArg]] = dict()
        # var_name -> set{potential values of var_name}
        self._obj: Dict[str, set] = dict()
        self.constructor_name: str = ""
        # display name to the actual method name in dis
        self._method_name_d: Dict[str, AsmArg] = dict()

    def set_var_local(self, idx: int, value: Union[str, AsmArg], force=True) -> bool:
        if (idx in self._var_local and force is False):
            Log.warn(f"set_var_local Failed, force {force} idx {idx} value {value}")
            return False
        self._var_local[idx] = value
        return True

    def get_var_local(self, idx: int = None) -> Union[str, AsmArg, Dict[int, Union[str, AsmArg]], None]:
        if (idx is None):
            return self._var_local
        if (idx in self._var_local):
            return self._var_local[idx]
        Log.warn(f"get_var_local Failed, idx {idx}")
        return None

    def set_obj(self, obj_name: str, value) -> bool:
        return self.add_obj_value(obj_name, value)

    def add_obj_value(self, obj_name: str, value) -> bool:
        if (obj_name not in self._obj):
            self._obj[obj_name] = set()
        self._obj[obj_name].add(value)
        return True

    def get_obj(self, obj_name: str = None) -> Union[set, Dict[str, set], None]:
        if (obj_name is None):
            return self._obj
        if (obj_name in self._obj):
            return self._obj[obj_name]
        Log.warn(f"get_var_local Failed, obj_name {obj_name}")
        return None

    def _debug_str(self) -> str:
        out = f"ModuleInfo {self.module_name}: var_local({len(self._var_local)}) obj({len(self._obj)})"
        return out

    def _debug_vstr(self) -> str:
        out = self._debug_str() + ": "
        out += f"var_local {self._var_local}; obj {self._obj}"
        return out

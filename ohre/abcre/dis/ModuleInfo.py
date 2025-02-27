import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.misc import Log, utils


class ModuleInfo(DebugBase):
    def __init__(self, module_name: str):
        self.module_name = module_name
        # idx -> modulevar / a imported module name(str)
        # NOTE: stmodulevar ldlocalmodulevar related
        self._var_local: Dict[int, Union[str, AsmArg]] = dict()
        # var_name -> set{potential values of var_name}
        self._obj: Dict[str, set] = dict()
        self.constructor_name: str = ""
        # display name to the actual method name in dis
        self._method_name_d: Dict[str, AsmArg] = dict()
        self._module_class: AsmArg = None
        # METHOD_OBJ[HomeObject] = CLASS , store method name of METHOD_OBJ
        self._HomeObject_method: set[str] = set()

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

    def get_module_class(self) -> AsmArg:
        return self._module_class

    def set_module_class(self, module_class: AsmArg) -> bool:
        if (self._module_class is None):
            self._module_class = copy.deepcopy(module_class)
            return True
        else:
            print(f"set_module_class old: {self._module_class} new: {module_class}")

    def set_HomeObject_method(self, module_method_name: str) -> bool:
        self._HomeObject_method.add(module_method_name)

    def _common_error_check(self):
        debug_module_name = set()
        for meth_name in self._HomeObject_method:
            module_name, method_name = utils.split_to_module_method_name(meth_name)
            debug_module_name.add(module_name)
        if (len(debug_module_name) > 1):
            Log.error(f"ERROR: more then 1 module name {len(self._HomeObject_method)} {self._HomeObject_method}")

    def _debug_str(self) -> str:
        self._common_error_check()
        out = f"ModuleInfo {self.module_name}: var_local({len(self._var_local)}) obj({len(self._obj)}) \
method_name_d({len(self._method_name_d)}) HomeObject_method({len(self._HomeObject_method)})"
        return out

    def _debug_vstr(self) -> str:
        self._common_error_check()
        out = self._debug_str() + ": "
        out += f"var_local: {self._var_local}; obj: {self._obj}; method_name_d: {self._method_name_d}; \
HomeObject_method: {self._HomeObject_method};"
        return out

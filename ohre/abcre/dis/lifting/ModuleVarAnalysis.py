from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.misc import Log, utils

# ObservedPropertySimplePU ObservedPropertyObjectPU # @State
# SynchedPropertySimpleOneWayPU SynchedPropertyObjectOneWayPU # @Prop

NEW_SIMPLE_PU = {"ObservedPropertySimplePU", "SynchedPropertySimpleOneWayPU"}


def is_property_obj_PU(call_addr: AsmArg) -> bool:
    if (call_addr.is_obj() and call_addr.name in NEW_SIMPLE_PU):
        return True
    return False


def is_func_set(call_addr: AsmArg) -> bool:
    if (call_addr.is_obj() and call_addr.name == "set"):
        return True
    return False


def ModuleVarAnalysis(dis_file: DisFile):
    for module_name, name_meth_d in dis_file.methods.items():
        for method_name, meth in name_meth_d.items():
            for cb in meth.code_blocks:
                for tac in cb.insts:
                    if (tac.type == TACTYPE.CALL and len(tac.args) >= 2):  # tac.args[1] is call addr
                        # create module var
                        if (is_property_obj_PU(tac.args[1])):
                            var_name = "EMPTY!"
                            if (len(tac.args) >= 6 and tac.args[5].is_str()):
                                var_name = tac.args[5].value
                            var_value = None
                            if (len(tac.args) >= 4 and tac.args[3].is_specific_like()):
                                var_value = tac.args[3].get_specific_value()
                            dis_file.new_module_var(meth.module_name, var_name, var_value)
                        # tac like this->xxx->set(v): set/add/append xxx's value
                        elif (is_func_set(tac.args[1]) and isinstance(tac.this, AsmArg)
                              and isinstance(tac.this.ref_base, AsmArg) and tac.this.ref_base.is_arg_this()):
                            if (len(tac.args) >= 4 and tac.args[3].is_specific_like()):
                                dis_file.set_module_var(meth.module_name, tac.this.name,
                                                        tac.args[3].get_specific_value())

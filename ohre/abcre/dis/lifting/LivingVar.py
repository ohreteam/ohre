from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.misc import Log, utils


def _update_method_current_cb_use_vars(meth: AsmMethod):
    for cb in meth.code_blocks:
        print(f"get_def_var processing {cb}")
        use_vars: set = set()
        for inst in cb.insts:
            def_inst, use_inst = inst.get_def_use()
            use_vars.update(use_inst)
        cb.set_use_vars(use_vars)

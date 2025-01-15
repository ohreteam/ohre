from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.misc import Log, utils


def _update_method_cbs_def_use_vars(meth: AsmMethod):
    for cb in meth.code_blocks:
        use_vars: set = set()
        def_vars: set = set()
        for inst in cb.insts:
            def_inst, use_inst = inst.get_def_use()
            use_vars.update(use_inst)
            def_vars.update(def_inst)
        cb.set_use_vars(use_vars)
        cb.set_def_vars(def_vars)

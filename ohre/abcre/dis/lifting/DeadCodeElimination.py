from typing import Any, Dict, Iterable, List, Tuple, Union
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.lifting.LivingVar import _update_method_current_cb_use_vars
from ohre.abcre.dis.enum.TACTYPE import TACTYPE

from ohre.abcre.dis.TAC import TAC


def DeadCodeElimination(meth: AsmMethod):
    # eliminate the var def but not used inside that code block and the following cbs
    # 1-Delete Dead Code: 1. cb without next cb; 2. def in cb 3. NOT used in cb
    # 2-Delete Dead Code: 1. def in cb 2. NOT used in cb and all next cbs
    # 3-Delete Dead Code: TODO: delete code def in the front but not used and then redef later
    print(f"\n\nDCE-START {meth.name} {meth.level_str}")

    inst_cnt_change = True
    while (inst_cnt_change):
        inst_cnt_change = False
        _update_method_current_cb_use_vars(meth)
        for cb in meth.code_blocks:
            old_insts_len = cb.get_insts_len()
            DCE_cb(cb)
            new_insts_len = cb.get_insts_len()
            print(f"old_insts_len {old_insts_len} new_insts_len {new_insts_len}")
            if (old_insts_len != new_insts_len):
                inst_cnt_change = True
        for cb in meth.code_blocks:
            print(f"DCE_cb END cb: {cb._debug_vstr()}\n")
    print(f"DCE-END {meth.name} {meth.level_str}\n\n ")


def DCE_cb(cb: CodeBlock):  # DCE is short for DeadCodeElimination
    # NOTE: reverse order traversal: update vars used into `used_after`
    # if a inst def a var NOT used at `used_after`, mark it as pending delete index set
    print(f"DCE_cb START cb: {cb} get_all_next_cbs_use_vars {cb.get_all_next_cbs_use_vars()}")
    # Step-1: reverse order, add inst that def a var not in current `used_after` into pending set
    used_after: set = cb.get_all_next_cbs_use_vars()
    pending_delete_inst_idxs: set = set()
    for i in range(cb.get_insts_len() - 1, -1, -1):
        def_inst, use_inst = cb.insts[i].get_def_use()
        used_after.update(use_inst)
        used_after_flag = False  # var def in this inst is used after this inst or not
        for var in def_inst:
            if (var in used_after):
                used_after_flag = True
                break
        if (used_after_flag == False):
            pending_delete_inst_idxs.add(i)
        print(f"{i} {cb.insts[i]} \t def: {def_inst} use: {use_inst} used_after? {used_after_flag}")
    cb.set_use_vars(used_after)

    # Step-2: determine: if idxs in pending delete inst idxs actually need to be deleted
    tac_l: List[TAC] = list()
    delete_inst_idx = set()
    for i in range(cb.get_insts_len()):
        if (cb.insts[i].type == TACTYPE.ASSIGN and i in pending_delete_inst_idxs):
            delete_inst_idx.add(i)
            continue
        tac_l.append(cb.insts[i])  # NOT delete
    print(f"DCE_cb delete_inst_idx {delete_inst_idx}")
    cb.replace_insts(tac_l)

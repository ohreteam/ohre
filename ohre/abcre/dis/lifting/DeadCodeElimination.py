from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.lifting.LivingVar import getLivingVar


def DeadCodeElimination(meth: AsmMethod):
    # TODO: eliminate the var def but not used inside that code block and following cbs
    print(f"DeadCodeElimination-START {meth.name} {meth.level_str}")
    getLivingVar(meth)

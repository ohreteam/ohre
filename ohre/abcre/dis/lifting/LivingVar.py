from ohre.abcre.dis.AsmMethod import AsmMethod


def get_def_var(meth: AsmMethod):
    for cb in meth.code_blocks:
        print(f"get_def_var processing {cb}")


def getLivingVar(meth: AsmMethod):
    print(f"getLivingVar-START {meth.name} {meth.level_str}")
    def_vars = get_def_var(meth)

from typing import Any, Dict, Iterable, List, Tuple

from ohre.abcre.dis.NACTYPE import NACTYPE


class TAC():  # Three Address Code

    def __init__(self, optype, op_args: List):
        self.optype = optype
        self.args = None

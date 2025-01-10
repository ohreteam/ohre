from abc import ABCMeta, abstractmethod


class DebugBase:
    __metaclass__ = ABCMeta

    def __init__(self):
        pass

    def __str__(self):
        return self._debug_str()

    def __repr__(self):
        return self._debug_str()

    @abstractmethod
    def _debug_str(self):
        pass

    @abstractmethod
    def _debug_vstr(self) -> str:
        pass

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.abcre.core.ForeignMethod import ForeignMethod
from typing import Any, Dict, List, Tuple
from ohre.abcre.enum.MethodTag import MethodTag
from ohre.misc import Log


class Method(ForeignMethod):
    def __init__(self, buf=None, pos: int = 0):
        super().__init__(buf, pos)
        # self.class_idx Corresponding index entry must be an offset to a Class.
        self._method_data_pos_start = self.pos_end
        # TaggedValue[] list of (uint8_t/MethodTag, uint8_t[])
        self.method_data: List[TaggedValue] = None
        self.method_data, self.pos_end = _read_method_data_TaggedValue(buf, self.pos_end)

    def __str__(self):
        out_tag_value = ""
        for t_v in self.method_data:
            if (t_v.tag == MethodTag.NOTHING):
                out_tag_value += f"{MethodTag.get_code_name(t_v.tag)}"
            elif (t_v.tag == MethodTag.CODE or
                  t_v.tag == MethodTag.RUNTIME_ANNOTATION or
                  t_v.tag == MethodTag.RUNTIME_PARAM_ANNOTATION or
                  t_v.tag == MethodTag.DEBUG_INFO or
                  t_v.tag == MethodTag.ANNOTATION or
                  t_v.tag == MethodTag.PARAM_ANNOTATION or
                  t_v.tag == MethodTag.TYPE_ANNOTATION or
                  t_v.tag == MethodTag.RUNTIME_TYPE_ANNOTATION):
                out_tag_value += f"{MethodTag.get_code_name(t_v.tag)} {hex(op._uint8_t_array4_to_int(t_v.data))}; "
            else:
                out_tag_value += f"{MethodTag.get_code_name(t_v.tag)} {t_v.data}; "
        out = f"Method: [{hex(self.pos_start)}/{hex(self.pos_end)}] {self.name} class_idx {hex(self.class_idx)} \
proto_idx {hex(self.proto_idx)} name_off {hex(self.name_off)} access_flags {hex(self.access_flags)} \
method_data({len(self.method_data)}) {out_tag_value}"
        return out


def _read_method_data_TaggedValue(buf, offset) -> Tuple[list[TaggedValue], int]:
    l_tag_value = list()
    while (True):
        tag, offset = op._read_uint8_t_offset(buf, offset)
        Log.debug(f"_read_method_data_TaggedValue MethodTag/offset {tag}/{hex(offset)}")
        t_v = TaggedValue(-1)
        if (tag == MethodTag.NOTHING):
            t_v = TaggedValue(MethodTag.NOTHING)
        elif (tag == MethodTag.CODE):
            CODE, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.CODE, CODE)
        elif (tag == MethodTag.SOURCE_LANG):
            SOURCE_LANG, offset = op._read_uint8_t_offset(buf, offset)
            t_v = TaggedValue(MethodTag.SOURCE_LANG, SOURCE_LANG)
        elif (tag == MethodTag.RUNTIME_ANNOTATION):
            RUNTIME_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.RUNTIME_ANNOTATION, RUNTIME_ANNOTATION)
        elif (tag == MethodTag.RUNTIME_PARAM_ANNOTATION):
            RUNTIME_PARAM_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.RUNTIME_PARAM_ANNOTATION, RUNTIME_PARAM_ANNOTATION)
        elif (tag == MethodTag.DEBUG_INFO):
            DEBUG_INFO, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.DEBUG_INFO, DEBUG_INFO)
        elif (tag == MethodTag.ANNOTATION):
            ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.ANNOTATION, ANNOTATION)
        elif (tag == MethodTag.PARAM_ANNOTATION):
            PARAM_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.PARAM_ANNOTATION, PARAM_ANNOTATION)
        elif (tag == MethodTag.TYPE_ANNOTATION):
            TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.TYPE_ANNOTATION, TYPE_ANNOTATION)
        elif (tag == MethodTag.RUNTIME_TYPE_ANNOTATION):
            RUNTIME_TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(MethodTag.RUNTIME_TYPE_ANNOTATION, RUNTIME_TYPE_ANNOTATION)
        else:
            Log.error(f"_read_method_data_TaggedValue: MethodTag NOT supported {tag} offset {offset}")
            exit()

        l_tag_value.append(t_v)
        if (tag == MethodTag.NOTHING):
            break
    return l_tag_value, offset

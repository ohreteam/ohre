import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.TaggedValue import TaggedValue
from typing import Any, Dict, List, Tuple
from ohre.abcre.enum.MethodTag import MethodTag
from ohre.misc import Log


class Method(BaseRegion):
    def __init__(self, buf=None, pos: int = 0):
        super().__init__(pos)
        if (buf is not None):
            self.class_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            self.proto_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
            self.name_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
            self.name = op._read_String(buf, self.name_off)
            self.access_flags, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
            self._method_data_pos_start = self.pos_end
            # TaggedValue[] list of (uint8_t/MethodTag, uint8_t[])
            self.method_data, self.pos_end = _read_method_data_TaggedValue(buf, self.pos_end)

    def __str__(self):
        out_tag_value = ""
        for tag_value in self.method_data:
            out_tag_value += f"{tag_value}; "
        out = f"Method: [{hex(self.pos_start)}/{hex(self.pos_end)}] {self.name} class_idx {hex(self.class_idx)} \
proto_idx {hex(self.proto_idx)} name_off {hex(self.name_off)} access_flags {hex(self.access_flags)} \
method_data({len(self.method_data)}) {out_tag_value}"
        return out


def _read_method_data_TaggedValue(buf, offset) -> Tuple[list[TaggedValue], int]:
    l_tag_value = list()
    while (True):
        tag, offset = op._read_uint8_t_offset(buf, offset)
        Log.debug(f"_read_method_data_TaggedValue MethodTag/offset {tag}/{hex(offset)}")
        tag_value = TaggedValue(-1)
        if (tag == MethodTag.NOTHING):
            tag_value = TaggedValue(MethodTag.NOTHING)
        elif (tag == MethodTag.CODE):
            CODE, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.CODE, CODE)
        elif (tag == MethodTag.SOURCE_LANG):
            SOURCE_LANG, offset = op._read_uint8_t_offset(buf, offset)
            tag_value = TaggedValue(MethodTag.SOURCE_LANG, SOURCE_LANG)
        elif (tag == MethodTag.RUNTIME_ANNOTATION):
            RUNTIME_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.RUNTIME_ANNOTATION, RUNTIME_ANNOTATION)
        elif (tag == MethodTag.RUNTIME_PARAM_ANNOTATION):
            RUNTIME_PARAM_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.RUNTIME_PARAM_ANNOTATION, RUNTIME_PARAM_ANNOTATION)
        elif (tag == MethodTag.DEBUG_INFO):
            DEBUG_INFO, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.DEBUG_INFO, DEBUG_INFO)
        elif (tag == MethodTag.ANNOTATION):
            ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.ANNOTATION, ANNOTATION)
        elif (tag == MethodTag.PARAM_ANNOTATION):
            PARAM_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.PARAM_ANNOTATION, PARAM_ANNOTATION)
        elif (tag == MethodTag.TYPE_ANNOTATION):
            TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.TYPE_ANNOTATION, TYPE_ANNOTATION)
        elif (tag == MethodTag.RUNTIME_TYPE_ANNOTATION):
            RUNTIME_TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            tag_value = TaggedValue(MethodTag.RUNTIME_TYPE_ANNOTATION, RUNTIME_TYPE_ANNOTATION)
        else:
            Log.error(f"_read_method_data_TaggedValue: MethodTag NOT supported {tag} offset {offset}")
            exit()

        l_tag_value.append(tag_value)
        if (tag == MethodTag.NOTHING):
            break
    return l_tag_value, offset

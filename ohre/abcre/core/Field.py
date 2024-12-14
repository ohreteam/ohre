from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.abcre.enum.FieldTag import FieldTag
from ohre.misc import Log


class Field(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        self.class_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.type_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.name_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.name = op._read_String(buf, self.name_off)
        self.reserved0, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        self.field_data: List[TaggedValue] = None  # TaggedValue[] list of (uint8_t/FieldTag, uint8_t[])
        # TODO: VALUE 0x02 FLOAT or ID in Value formats
        self.field_data, self.pos_end = _read_field_data_TaggedValue(buf, self.pos_end)

    def __str__(self):
        out_field_data = ""
        for t_v in self.field_data:
            if (t_v.tag == FieldTag.NOTHING):
                out_field_data += f"{FieldTag.get_code_name(t_v.tag)}"
            elif (t_v.tag == FieldTag.INT_VALUE):
                out_field_data += f"{FieldTag.get_code_name(t_v.tag)} {hex(t_v.data)}; "
            elif (t_v.tag == FieldTag.VALUE):
                out_field_data += \
                    f"{FieldTag.get_code_name(t_v.tag)} {hex(t_v.data)} or {op._uint32_t_to_float32(t_v.data)}; "
            elif (t_v.tag == FieldTag.RUNTIME_ANNOTATIONS or
                  t_v.tag == FieldTag.ANNOTATIONS or
                  t_v.tag == FieldTag.RUNTIME_TYPE_ANNOTATION or
                  t_v.tag == FieldTag.TYPE_ANNOTATION):
                out_field_data += f"{FieldTag.get_code_name(t_v.tag)} {hex(op._uint8_t_array_to_int(t_v.data))}; "
                Log.info(f"TAG not supported: {FieldTag.get_code_name(t_v.tag)}")
            else:
                out_field_data += f"{FieldTag.get_code_name(t_v.tag)} {t_v.data}; "

        out = f"Field: [{hex(self.pos_start)}/{hex(self.pos_end)}] {self.name} class_idx {hex(self.class_idx)} \
type_idx {hex(self.type_idx)} name_off {hex(self.name_off)} reserved0 {hex(self.reserved0)} \
field_data({len(self.field_data)}) {out_field_data}"
        return out


def _read_field_data_TaggedValue(buf, offset) -> Tuple[list[TaggedValue], int]:
    l_tag_value = list()
    while (True):
        tag, offset = op._read_uint8_t_offset(buf, offset)
        Log.debug(f"_read_field_data_TaggedValue tag/offset {tag}/{hex(offset)}")
        t_v = TaggedValue(-1)
        if (tag == FieldTag.NOTHING):
            t_v = TaggedValue(FieldTag.NOTHING)
        elif (tag == FieldTag.INT_VALUE):
            INT_VALUE, offset = op._read_sleb128_offset(buf, offset)
            t_v = TaggedValue(FieldTag.INT_VALUE, INT_VALUE)
        elif (tag == FieldTag.VALUE):
            VALUE, offset = op._read_uint32_t_offset(buf, offset)
            t_v = TaggedValue(FieldTag.VALUE, VALUE)
        elif (tag == FieldTag.RUNTIME_ANNOTATIONS):
            RUNTIME_ANNOTATIONS, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(FieldTag.RUNTIME_ANNOTATIONS, RUNTIME_ANNOTATIONS)
        elif (tag == FieldTag.ANNOTATIONS):
            ANNOTATIONS, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(FieldTag.ANNOTATIONS, ANNOTATIONS)
        elif (tag == FieldTag.RUNTIME_TYPE_ANNOTATION):
            RUNTIME_TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(FieldTag.RUNTIME_TYPE_ANNOTATION, RUNTIME_TYPE_ANNOTATION)
        elif (tag == FieldTag.TYPE_ANNOTATION):
            TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(FieldTag.TYPE_ANNOTATION, TYPE_ANNOTATION)
        else:
            Log.error(f"_read_field_data_TaggedValue: tag NOT supported {tag} offset {offset}")
            exit()

        l_tag_value.append(t_v)
        if (tag == FieldTag.NOTHING):
            break
    return l_tag_value, offset

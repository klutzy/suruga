// TODO remove debug line
macro_rules! der_err {
    ($kind:expr, $($args:tt)*) => ({
        let e = format!($($args)*);
        let e = format!("{} {} / {}", file!(), line!(), e);
        ::der::DerError::new($kind, e)
    })
}

macro_rules! from_sequence {
    ($seq_name:ident) => (
        impl $crate::der::FromTlv for $seq_name {
            fn from_tlv(tag: $crate::der::Tag, value: &[u8]) -> $crate::der::DerResult<$seq_name> {
                match tag {
                    ::der::Tag::Sequence => {
                        let seq_parser = $crate::der::reader::DerReader::new(value);
                        let result: $seq_name = try!($seq_name::from_seq(seq_parser));
                        Ok(result)
                    }
                    _ => return der_err!($crate::der::DerErrorKind::InvalidTag,
                                         "unexpected tag: {:?}",
                                         tag),
                }
            }
        }

    )
}

macro_rules! from_value {
    ($ty_name:ty: $base_tag:pat) => (
        impl ::der::FromTlv for $ty_name {
            fn from_tlv(tag: ::der::Tag, value: &[u8]) -> ::der::DerResult<$ty_name> {
                match tag {
                    $base_tag => ::der::FromValue::from_value(value),
                    _ => return der_err!($crate::der::DerErrorKind::InvalidTag,
                                         "unexpected tag: {:?}",
                                         tag),
                }
            }
        }
    )
}

macro_rules! ctx_sp {
    (P, $e:expr) => (
        ::der::Tag::Primitive($e, $crate::der::TagClass::ContextSpecific)
    );
    (C, $e:expr) => (
        ::der::Tag::Constructed($e, $crate::der::TagClass::ContextSpecific)
    );
}

macro_rules! sequence {
    (
        $(#[$a:meta])*
        struct $seq_name:ident {
            $(
                $item_name:ident: $item_ty:ty,
            )+
        }
    ) => (
        sequence_opts!(
            $(#[$a])*
            struct $seq_name {
                $(
                    $item_name(): $item_ty,
                )+
            }
        );
    )
}

macro_rules! sequence_opts {
    (
        $(#[$a:meta])*
        struct $seq_name:ident {
            $(
                $item_name:ident($($opts:tt)*): $item_ty:ty,
            )+
        }
    ) => (
        $(#[$a])*
        #[derive(Debug)]
        pub struct $seq_name {
            $(
                pub $item_name: $item_ty,
            )+
        }

        from_sequence!($seq_name);

        impl $seq_name {
            fn from_seq(mut parser: $crate::der::reader::DerReader)
            -> $crate::der::DerResult<$seq_name> {
                $(
                    let $item_name: $item_ty = {
                        let ret = sequence_item!($item_ty, parser, $($opts)*);
                        ret
                    };
                )+

                if let Some((tag, value)) = try!(parser.peek_tlv()) {
                    return der_err!($crate::der::DerErrorKind::InvalidTag,
                                    "should be no element left, found {:?} in {}",
                                    (tag, value),
                                    stringify!($seq_name));
                }

                Ok($seq_name {
                    $(
                        $item_name: $item_name,
                    )+
                })
            }
        }
    )
}

macro_rules! sequence_item {
    ($t:ty, $parser:expr,) => ({
        let (tag, value) = try!($parser.next_tlv());
        let result: $t = try!($crate::der::FromTlv::from_tlv(tag, value));
        result
    });
    ($t:ty, $parser:expr, OPTIONAL, $($tag:path),+) => ({
        match try!($parser.peek_tlv()) {
            None => None,
            Some((tag, value)) => {
                if $(tag == $tag)||+ {
                    $parser.bump();
                    // `$t` is `Option<T>`
                    let result: $t = Some(try!($crate::der::FromTlv::from_tlv(tag, value)));
                    result
                } else {
                    None
                }
            }
        }
    });
    ($t:ty, $parser:expr, DEFAULT, $default:expr, $($tag:path),+) => ({
        match try!($parser.peek_tlv()) {
            None => $default,
            Some((tag, value)) => {
                if $(tag == $tag)||+ {
                    $parser.bump();
                    let result: $t = try!($crate::der::FromTlv::from_tlv(tag, value));
                    // NOTE: DER requires `result != $default`,
                    // but invalid cases are found in practice:
                    // https://bugzilla.mozilla.org/show_bug.cgi?id=1031093
                    // we may just have to disable it later.
                    if result == $default {
                        return der_err!($crate::der::DerErrorKind::InvalidVal,
                                        "value identical to default: {}",
                                        result);
                    }
                    result
                } else {
                    $default
                }
            }
        }
    });
    ($t:ty, $parser:expr, IMPLICIT_OPTIONAL[$cls:ident:$id:expr], $orig_tag:path) => ({
        match try!($parser.peek_tlv()) {
            None => None,
            Some((tag, value)) => {
                if tag == ctx_sp!($cls, $id) {
                    $parser.bump();
                    let result: $t = Some(try!($crate::der::FromTlv::from_tlv($orig_tag, value)));
                    result
                } else {
                    None
                }
            }
        }
    });
    ($t:ty, $parser:expr, EXPLICIT_OPTIONAL[$cls:ident:$id:expr]) => ({
        try!($parser.explicit(ctx_sp!($cls, $id),
            |tag, value: &[u8]| {
                let result = try!($crate::der::FromTlv::from_tlv(tag, value));
                Ok(Some(result))
            },
            || Ok(None)
        ))
    });
    ($t:ty, $parser:expr, EXPLICIT_DEFAULT[$cls:ident:$id:expr], $def:expr) => ({
        try!($parser.explicit(ctx_sp!($cls, $id),
            |tag, value: &[u8]| {
                let result = try!($crate::der::FromTlv::from_tlv(tag, value));
                Ok(result)
            },
            || Ok($def)
        ))
    });
}

macro_rules! sequence_of {
    (
        struct $seq_name:ident = $item_ty:ident($len_min:expr)
    ) => (
        #[derive(Debug)]
        pub struct $seq_name {
            pub seq: Vec<$item_ty>,
        }

        impl ::der::FromTlv for $seq_name {
            fn from_tlv(tag: ::der::Tag, value: &[u8]) -> ::der::DerResult<$seq_name> {
                match tag {
                    ::der::Tag::Sequence => {
                        let seq_parser = $crate::der::reader::DerReader::new(value);
                        let value: $seq_name = try!($seq_name::from_seq(seq_parser));
                        Ok(value)
                    }
                    _ => return der_err!($crate::der::DerErrorKind::InvalidTag,
                                         "expected Seq, unexpected tag: {:?}",
                                         tag),
                }
            }

        }

        impl $seq_name {
            fn from_seq(mut parser: ::der::reader::DerReader) -> ::der::DerResult<$seq_name> {
                let mut seq: Vec<$item_ty> = Vec::new();

                while !parser.is_eof() {
                    let (tag, value) = try!(parser.next_tlv());
                    let item: $item_ty = try!($crate::der::FromTlv::from_tlv(tag, value));
                    seq.push(item);
                }

                let len_min: usize = $len_min;

                if seq.len() < len_min {
                    return der_err!($crate::der::DerErrorKind::InvalidVal,
                                    "sequence shorter than {}",
                                    len_min);
                }

                Ok($seq_name {
                    seq: seq,
                })
            }
        }
    )
}

macro_rules! bit_string_fields {
    (
        struct $name:ident {
            $(
                $bit_name:ident($i:expr),
            )+
        }
    ) => (
        #[derive(Debug)]
        pub struct $name {
            $(
                pub $bit_name: bool,
            )+
        }

        from_value!($name: Tag::BitString);

        impl FromValue for $name {
            fn from_value(value: &[u8]) -> DerResult<$name> {
                let (unused_bits, value) = try!(::der::bit_string::from_der(value));
                let total_bits = value.len() * 8 - unused_bits as usize;

                // TODO `11100000` <- trailing bits should be disallowed
                $(
                    let byte_offset = $i / 8;
                    let $bit_name: bool = if $i < total_bits {
                        (value[byte_offset] >> (7 - ($i % 8))) & 1 == 1
                    } else {
                        false
                    };
                )+

                Ok($name {
                    $(
                        $bit_name: $bit_name,
                    )+
                })
            }
        }
    )
}

// parses the following form:
// SEQUENCE {
//     id OBJECT IDENTIFIER,
//     value ANY DEFINED BY id
// }
macro_rules! enum_obj_id {
    (
        enum $enum_name:ident {
            $(
                $name:ident($t:ty) = $val:pat,
            )+
        }
    ) => (
        #[derive(Debug)]
        pub enum $enum_name {
            $(
                $name($t),
            )+

            Unknown,
        }

        from_sequence!($enum_name);
        impl $enum_name {
            fn from_seq(mut reader: DerReader) -> DerResult<$enum_name> {
                // FIXME: this exists only because `id` freezes reader.
                #[derive(Debug)]
                enum ObjId {
                    $(
                        $name,
                    )+

                    Unknown,
                }

                let ext = {
                    let (tag, id) = try!(reader.next_tlv());
                    if tag != Tag::ObjectIdentifier {
                        return der_err!(::der::DerErrorKind::InvalidTag,
                                        "expected ObjectIdentifier, found {:?}",
                                        tag);
                    }

                    let ext = match id {
                        $(
                            $val => ObjId::$name,
                        )+
                        _ => ObjId::Unknown,
                    };
                    debug!("id: {:?} -> {:?}", id, ext);
                    ext
                };

                match ext {
                    $(
                        ObjId::$name => {
                            let (tag, value) = try!(reader.next_tlv());
                            debug!("ext tag {:?} value {:?}", tag, value);
                            let result: $t = try!(FromTlv::from_tlv(tag, value));
                            if !reader.is_eof() {
                                return der_err!(::der::DerErrorKind::InvalidTag,
                                                "too many TLV elements");
                            }
                            debug!("result: {}, {:?}", stringify!($name), result);
                            return Ok($enum_name::$name(result));
                        }
                    )+
                    ObjId::Unknown => {
                        return Ok($enum_name::Unknown);
                    }
                }
            }
        }
    )
}

// macro for enum based on one-byte integer
// e.g. `INTEGER { two-prime(0), multi(1) }`
macro_rules! enum_integer {
    (
        enum $enum_name:ident {
            $(
                $name:ident = $val:pat,
            )+
        }
    ) => (
        #[derive(Debug)]
        #[derive(PartialEq)]
        pub enum $enum_name {
            $(
                $name,
            )+
        }

        from_value!($enum_name: $crate::der::Tag::Integer);

        impl $crate::der::FromValue for $enum_name {
            fn from_value(value: &[u8]) -> $crate::der::DerResult<$enum_name> {
                let len = value.len();
                if len != 1 {
                    return der_err!($crate::der::DerErrorKind::InvalidVal,
                                    "expected length 1, found {}", len);
                }
                let value = match value[0] {
                     $(
                        $val => $enum_name::$name,
                     )+
                     other => return der_err!($crate::der::DerErrorKind::InvalidVal,
                                              "unknown value: {}", other),
                };
                Ok(value)
            }
        }
    )
}

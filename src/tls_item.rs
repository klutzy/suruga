use tls_result::TlsResult;

pub trait TlsItem {
    fn tls_write<W: Writer>(&self, writer: &mut W) -> TlsResult<()>;
    fn tls_read<R: Reader>(reader: &mut R) -> TlsResult<Self>;
    fn tls_size(&self) -> u64;
}

macro_rules! tls_primitive {
    ($t:ident) => (
        impl TlsItem for $t {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                stry_write_num!($t, writer, *self);
                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<$t> {
                let u = stry_read_num!($t, reader);
                Ok(u)
            }

            fn tls_size(&self) -> u64 { num_size!($t) }
        }
    )
}

tls_primitive!(u8);
tls_primitive!(u16);
tls_primitive!(u32);

macro_rules! tls_struct {
    (
        struct $name:ident {
            $(
                $item:ident: $t:ty
            ),+
        }
    ) => (
        pub struct $name {
            $(
                pub $item: $t,
            )+
        }

        impl TlsItem for $name {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                $(
                    try!(self.$item.tls_write(writer));
                )+

                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
                $(
                    let $item: $t = try!(TlsItem::tls_read(reader));
                )+

                let result = $name {
                    $(
                        $item: $item,
                    )+
                };
                Ok(result)
            }

            fn tls_size(&self) -> u64 {
                let mut size = 0;
                $(
                    size += self.$item.tls_size();
                )+

                size
            }
        }
    )
}

macro_rules! tls_enum {
    (
        $repr_ty:ident,
        $(#[$a:meta])*
        enum $name:ident {
            $(
                $item:ident($n:expr)
            ),+
        }
    ) => (
        #[allow(non_camel_case_types)]
        #[derive(Copy, PartialEq, FromPrimitive)]
        $(#[$a])*
        pub enum $name {
            $(
                $item = $n,
            )+
        }

        impl TlsItem for $name {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                stry_write_num!($repr_ty, writer, *self);
                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
                let num = stry_read_num!($repr_ty, reader) as u64;
                let n: Option<$name> = ::std::num::FromPrimitive::from_u64(num);
                match n {
                    Some(n) => Ok(n),
                    None => tls_err!(::tls_result::TlsErrorKind::DecodeError,
                                     "unexpected number: {}", num),
                }
            }

            fn tls_size(&self) -> u64 {
                num_size!($repr_ty)
            }
        }
    )
}

// usage:
// struct {
//     Type type;
//     "opaque" {
//         select (type) {
//             case TypeVariant1:
//                 ...
//             case TypeVariant2:
//                 ...
//         }
//     }
// } Struct;
macro_rules! tls_enum_struct {
    (
        $repr_ty:ident,
        $(#[$a:meta])*
        enum $enum_name:ident {
            $(
                $name:ident($body_ty:ident) = $num:tt // $num: integer literal
            ),+
        }
    ) => (
        #[allow(non_camel_case_types)]
        $(#[$a])*
        pub enum $enum_name {
            $(
                $name($body_ty),
            )+
        }

        impl TlsItem for $enum_name {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                match *self {
                    $(
                        $enum_name::$name(ref body) => {
                            stry_write_num!($repr_ty, writer, tt_to_expr!($num));
                            try!(body.tls_write(writer));
                        }
                    )+
                }
                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<$enum_name> {
                let num = stry_read_num!($repr_ty, reader);
                match num {
                    $(
                        tt_to_pat!($num) => {
                            let body: $body_ty = try!(TlsItem::tls_read(reader));
                            Ok($enum_name::$name(body))
                        }
                    )+
                    _ => return tls_err!(::tls_result::TlsErrorKind::DecodeError,
                                         "unexpected value: {}", num),
                }
            }

            fn tls_size(&self) -> u64 {
                let prefix_size = num_size!($repr_ty);
                let body_size = match *self {
                    $(
                        $enum_name::$name(ref body) => body.tls_size(),
                    )+
                };
                prefix_size + body_size
            }
        }
    )
}

// fixed-sized u8/opaque array
macro_rules! tls_array {
    ($name:ident = [u8, ..$n:expr]) => (
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(v: Vec<u8>) -> $crate::tls_result::TlsResult<$name> {
                let n: usize = $n;
                let len = v.len();
                if len != n {
                    return tls_err!($crate::tls_result::TlsErrorKind::InternalError,
                                    "bad size: {} != {}", len, n);
                } else {
                    Ok($name(v))
                }
            }

            pub fn as_slice<'a>(&'a self) -> &'a [u8] {
                let $name(ref v) = *self;
                v.as_slice()
            }
        }

        impl TlsItem for $name {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> $crate::tls_result::TlsResult<()> {
                let $name(ref data) = *self;
                try!(writer.write(data.as_slice()));
                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> $crate::tls_result::TlsResult<$name> {
                let data = try!(reader.read_exact($n));
                Ok($name(data))
            }

            fn tls_size(&self) -> u64 {
                $n
            }
        }
    )
}

macro_rules! tls_vec {
    // $item_ty must implement TlsItem
    ($name:ident = $item_ty:ident($size_min:expr, $size_max:expr)) => (
        pub struct $name(Vec<$item_ty>);
        impl $name {
            pub fn new(v: Vec<$item_ty>) -> $crate::tls_result::TlsResult<$name> {
                #![allow(unused_comparisons)] // disable warnings for e.g. `size < 0`

                let size_min: u64 = $size_min;
                let size_max: u64 = $size_max;

                let ret = $name(v);
                let size: u64 = ret.data_size();
                if size < size_min {
                    return tls_err!($crate::tls_result::TlsErrorKind::DecodeError,
                                    "bad size: {} < {}",
                                    size,
                                    size_min);
                } else if size > size_max {
                    return tls_err!($crate::tls_result::TlsErrorKind::DecodeError,
                    "bad size: {} > {}",
                    size,
                    size_max);
                } else {
                    Ok(ret)
                }
            }

            pub fn as_slice<'a>(&'a self) -> &'a [$item_ty] {
                let $name(ref v) = *self;
                v.as_slice()
            }

            pub fn unwrap(self) -> Vec<$item_ty> {
                let $name(data) = self;
                data
            }

            fn data_size(&self) -> u64 {
                let mut size = 0u64;
                for item in (**self).iter() {
                    size += item.tls_size();
                }
                size
            }
        }

        impl TlsItem for $name {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                let len = self.data_size();

                let size_max: u64 = $size_max;

                if size_max < 1 << 8 {
                    stry_write_num!(u8, writer, len);
                } else if size_max < 1 << 16 {
                    stry_write_num!(u16, writer, len);
                } else if size_max < 1 << 24 {
                    stry_write_num!(u24, writer, len);
                } else if size_max < 1 << 32 {
                    stry_write_num!(u32, writer, len);
                } else {
                    stry_write_num!(u64, writer, len);
                }

                for item in (**self).iter() {
                    try!(item.tls_write(writer));
                }

                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
                let size_max: u64 = $size_max;

                let self_size = if size_max < 1 << 8 {
                    (stry_read_num!(u8, reader)) as u64
                } else if size_max < 1 << 16 {
                    (stry_read_num!(u16, reader)) as u64
                } else if size_max < 1 << 24 {
                    (stry_read_num!(u24, reader)) as u64
                } else if size_max < 1 << 32 {
                    (stry_read_num!(u32, reader)) as u64
                } else {
                    (stry_read_num!(u64, reader)) as u64
                };

                let mut items_size = 0u64;
                let mut items = Vec::new();
                while items_size < self_size {
                    let item: $item_ty = try!(TlsItem::tls_read(reader));
                    items_size += item.tls_size();
                    items.push(item);
                }
                if items_size != self_size {
                    return tls_err!(::tls_result::TlsErrorKind::DecodeError,
                                    "wrong size: {} expected, {} found",
                                    self_size,
                                    items_size);
                }

                $name::new(items)
            }

            fn tls_size(&self) -> u64 {
                let mut size = 0;

                let size_max: u64 = $size_max;

                if size_max < 1 << 8 {
                    size += 1;
                } else if size_max < 1 << 16 {
                    size += 2;
                } else if size_max < 1 << 24 {
                    size += 3;
                } else if size_max < 1 << 32 {
                    size += 4;
                } else {
                    size += 8;
                }

                size += self.data_size();
                size
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = [$item_ty];
            fn deref<'a>(&'a self) -> &'a [$item_ty] {
                &self.0[]
            }
        }
    )
}

// this only works when the item is at the last
macro_rules! tls_option {
    ($t:ty) => (
        impl TlsItem for Option<$t> {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                match *self {
                    Some(ref data) => {
                        try!(data.tls_write(writer));
                    }
                    None => {}
                }
                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> ::tls_result::TlsResult<Option<$t>> {
                let rest = reader.read_to_end();
                match rest {
                    Ok(rest) => {
                        if rest.len() == 0 {
                            return Ok(None);
                        }

                        let mut rest_reader = ::std::io::MemReader::new(rest);
                        let extensions: $t = try!(TlsItem::tls_read(&mut rest_reader));
                        Ok(Some(extensions))
                    }
                    Err(err) => {
                        // read_to_end handles EndOfFile
                        // FIXME isn't this internal and/or io error?
                        return tls_err!(::tls_result::TlsErrorKind::DecodeError,
                                        "failed to read extensions: {}",
                                        err);
                    }
                }
            }

            fn tls_size(&self) -> u64 {
                match *self {
                    Some(ref data) => data.tls_size(),
                    None => 0,
                }
            }
        }
    )
}

// for macros
pub struct DummyItem;

impl TlsItem for DummyItem {
    fn tls_write<W: Writer>(&self, _writer: &mut W) -> TlsResult<()> { Ok(()) }
    fn tls_read<R: Reader>(_reader: &mut R) -> TlsResult<DummyItem> { Ok(DummyItem) }
    fn tls_size(&self) -> u64 { 0 }
}

// this is not "opaque" vector - this is totally unknown and only meaningful for receiving.
// it is assumed that the data is at the end of stream. (calls `Reader.read_to_end()`)
pub struct ObscureData(Vec<u8>);

impl TlsItem for ObscureData {
    fn tls_write<W: Writer>(&self, writer: &mut W) -> TlsResult<()> {
        try!(writer.write(self.as_slice()));
        Ok(())
    }

    fn tls_read<R: Reader>(reader: &mut R) -> TlsResult<ObscureData> {
        let data = try!(reader.read_to_end());
        Ok(ObscureData(data))
    }

    fn tls_size(&self) -> u64 { self.as_slice().len() as u64 }
}

impl ObscureData {
    pub fn new(data: Vec<u8>) -> ObscureData {
        ObscureData(data)
    }

    pub fn as_slice(&self) -> &[u8] {
        let ObscureData(ref data) = *self;
        data.as_slice()
    }

    pub fn unwrap(self) -> Vec<u8> {
        let ObscureData(data) = self;
        data
    }
}

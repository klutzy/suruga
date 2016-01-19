//! `TlsItem` represents item types that are serialized into TLS stream.
//!
//! There are several macros implementing common patterns:
//!
//! -   `tls_array` for fixed-length vector
//! -   `tls_vec` for variable-length vector
//! -   `tls_enum` for TLS enum type
//! -   `tls_struct` for TLS constructed type
//! -   `tls_option` for `Option<T>`

use std::io::prelude::*;

use util::{ReadExt, WriteExt};
use tls_result::TlsResult;

/// A trait for items that can be serialized at TLS stream.
pub trait TlsItem {
    /// Write an item into TLS stream.
    fn tls_write<W: WriteExt>(&self, writer: &mut W) -> TlsResult<()>;
    /// Read an item from TLS stream.
    fn tls_read<R: ReadExt>(reader: &mut R) -> TlsResult<Self>;
    /// Returns the length of serialized bytes.
    fn tls_size(&self) -> u64;
}

// implementation of `TlsItem` for primitive integer types like `u8`
macro_rules! tls_primitive {
    ($t:ident) => (
        impl TlsItem for $t {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                try_write_num!($t, writer, *self);
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<$t> {
                let u = try_read_num!($t, reader);
                Ok(u)
            }

            fn tls_size(&self) -> u64 { num_size!($t) }
        }
    )
}

tls_primitive!(u8);
tls_primitive!(u16);
tls_primitive!(u32);
tls_primitive!(u64);

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
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                $(
                    try!(self.$item.tls_write(writer));
                )+

                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
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
        enum_from_primitive! {
            #[allow(non_camel_case_types)]
            #[derive(Copy, Clone, PartialEq)]
            $(#[$a])*
            pub enum $name {
                $(
                    $item = $n,
                )+
            }
        }

        impl TlsItem for $name {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                try_write_num!($repr_ty, writer, *self);
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
                let num = try_read_num!($repr_ty, reader) as u64;
                let n: Option<$name> = ::num::traits::FromPrimitive::from_u64(num);
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
        }

        impl TlsItem for $name {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> $crate::tls_result::TlsResult<()> {
                try!(writer.write(&self.0));
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> $crate::tls_result::TlsResult<$name> {
                let data = try!(ReadExt::read_exact(reader, $n));
                Ok($name(data))
            }

            fn tls_size(&self) -> u64 {
                $n
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = [u8];
            fn deref<'a>(&'a self) -> &'a [u8] {
                &self.0
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
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                let len = self.data_size();

                let size_max: u64 = $size_max;

                if size_max < 1 << 8 {
                    try_write_num!(u8, writer, len);
                } else if size_max < 1 << 16 {
                    try_write_num!(u16, writer, len);
                } else if size_max < 1 << 24 {
                    try_write_num!(u24, writer, len);
                } else if size_max < 1 << 32 {
                    try_write_num!(u32, writer, len);
                } else {
                    try_write_num!(u64, writer, len);
                }

                for item in (**self).iter() {
                    try!(item.tls_write(writer));
                }

                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<$name> {
                let size_max: u64 = $size_max;

                let self_size = if size_max < 1 << 8 {
                    (try_read_num!(u8, reader)) as u64
                } else if size_max < 1 << 16 {
                    (try_read_num!(u16, reader)) as u64
                } else if size_max < 1 << 24 {
                    (try_read_num!(u24, reader)) as u64
                } else if size_max < 1 << 32 {
                    (try_read_num!(u32, reader)) as u64
                } else {
                    (try_read_num!(u64, reader)) as u64
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
                &self.0
            }
        }
    )
}

// this only works when the item is at the last of stream
macro_rules! tls_option {
    ($t:ty) => (
        impl TlsItem for Option<$t> {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                match *self {
                    Some(ref data) => {
                        try!(data.tls_write(writer));
                    }
                    None => {}
                }
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<Option<$t>> {
                let mut rest = vec![];
                let len = try!(reader.read_to_end(&mut rest));
                if len == 0 {
                    return Ok(None);
                }

                let mut rest_reader = ::std::io::Cursor::new(rest);
                let extensions: $t = try!(TlsItem::tls_read(&mut rest_reader));
                Ok(Some(extensions))
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
    fn tls_write<W: WriteExt>(&self, _writer: &mut W) -> TlsResult<()> { Ok(()) }
    fn tls_read<R: ReadExt>(_reader: &mut R) -> TlsResult<DummyItem> { Ok(DummyItem) }
    fn tls_size(&self) -> u64 { 0 }
}

// obsucre data received from TLS stream.
// since the semantic is unknown, it is only meaningful to read until end of stream is reached.
pub struct ObscureData(Vec<u8>);

impl TlsItem for ObscureData {
    fn tls_write<W: WriteExt>(&self, writer: &mut W) -> TlsResult<()> {
        try!(writer.write_all(&self.0));
        Ok(())
    }

    fn tls_read<R: ReadExt>(reader: &mut R) -> TlsResult<ObscureData> {
        let mut data = vec![];
        let _len = try!(reader.read_to_end(&mut data));
        Ok(ObscureData(data))
    }

    fn tls_size(&self) -> u64 { self.0.len() as u64 }
}

impl ObscureData {
    pub fn new(data: Vec<u8>) -> ObscureData {
        ObscureData(data)
    }

    pub fn unwrap(self) -> Vec<u8> {
        let ObscureData(data) = self;
        data
    }
}

impl ::std::ops::Deref for ObscureData {
    type Target = [u8];
    fn deref<'a>(&'a self) -> &'a [u8] {
        &self.0
    }
}

use std::{mem, fmt};
use std::error::Error;
use std::io::{self, Read, Write};

#[derive(Debug)]
pub struct SurugaError {
    pub desc: &'static str,
    pub cause: Option<Box<Error + Send + Sync + 'static>>,
}

impl fmt::Display for SurugaError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, fmt)
    }
}

impl Error for SurugaError {
    fn description(&self) -> &str {
        self.desc
    }

    // FIXME: implement fn cause(&self) -> Option<&Error>
    // This runs into difficulties with differing trait bounds.
}

/// constant-time compare function.
/// `a` and `b` may be SECRET, but the length is known.
/// precondition: `a.len() == b.len()`
pub fn crypto_compare(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());

    let mut diff = 0u8;
    for i in (0..a.len()) {
        diff |= a[i] ^ b[i];
    }
    diff = diff | (diff >> 4);
    diff = diff | (diff >> 2);
    diff = diff | (diff >> 1);
    diff = diff & 1;
    return diff == 0;
}

pub fn u64_be_array(x: u64) -> [u8; 8] {
    unsafe { mem::transmute(x.to_be()) }
}

pub fn u64_le_array(x: u64) -> [u8; 8] {
    unsafe { mem::transmute(x.to_le()) }
}

// native endians.
macro_rules! read_write_prim {
    ($read_name:ident, $write_name:ident, $t:ty, $len:expr) => (
        #[inline(always)]
        fn $read_name<R: ?Sized + ReadExt>(mut reader: &mut R) -> io::Result<$t> {
            let mut buf = [0u8; $len];
            try!(reader.fill_exact(&mut buf));
            let value: $t = unsafe { mem::transmute(buf) };
            Ok(value)
        }
        #[inline(always)]
        fn $write_name<R: ?Sized + Write>(mut writer: &mut R, value: $t) -> io::Result<()> {
            let buf: [u8; $len] = unsafe { mem::transmute(value) };
            try!(writer.write_all(&buf));
            Ok(())
        }
    )
}

read_write_prim!(read_u8, write_u8, u8, 1);
read_write_prim!(read_u16, write_u16, u16, 2);
read_write_prim!(read_u32, write_u32, u32, 4);
read_write_prim!(read_u64, write_u64, u64, 8);

pub trait ReadExt: Read {
    /// Fill buf completely or return `Err`.
    /// NOTE: the default implementation returns `Err(io::ErrorKind::Other)` if EOF is found.
    /// this may be not desired if the source is non-blocking.
    #[inline(always)]
    fn fill_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let len = buf.len();
        let mut pos = 0;
        while pos < len {
            let num_bytes = try!(self.read(&mut buf[pos..]));
            if num_bytes == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, SurugaError {
                    desc: "EOF during `fill_exact`",
                    cause: None
                }));
            }
            pos += num_bytes;
        }
        Ok(())
    }

    #[inline(always)]
    fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {
        // FIXME this can be more efficient using unsafe methods
        let mut vec = vec![0u8; len];
        try!(self.fill_exact(&mut vec));
        Ok(vec)
    }

    #[inline(always)]
    fn read_u8(&mut self) -> io::Result<u8> {
        read_u8(self)
    }
    #[inline(always)]
    fn read_be_u16(&mut self) -> io::Result<u16> {
        let value: u16 = try!(read_u16(self));
        Ok(value.to_be())
    }
    #[inline(always)]
    fn read_le_u16(&mut self) -> io::Result<u16> {
        let value: u16 = try!(read_u16(self));
        Ok(value.to_le())
    }
    #[inline(always)]
    fn read_be_u32(&mut self) -> io::Result<u32> {
        let value: u32 = try!(read_u32(self));
        Ok(value.to_be())
    }
    #[inline(always)]
    fn read_le_u32(&mut self) -> io::Result<u32> {
        let value: u32 = try!(read_u32(self));
        Ok(value.to_le())
    }
    #[inline(always)]
    fn read_be_u64(&mut self) -> io::Result<u64> {
        let value: u64 = try!(read_u64(self));
        Ok(value.to_be())
    }
    #[inline(always)]
    fn read_le_u64(&mut self) -> io::Result<u64> {
        let value: u64 = try!(read_u64(self));
        Ok(value.to_le())
    }
}

impl<R: Read> ReadExt for R {}

pub trait WriteExt: Write {
    #[inline(always)]
    fn write_u8(&mut self, value: u8) -> io::Result<()> {
        write_u8(self, value)
    }

    #[inline(always)]
    fn write_be_u16(&mut self, value: u16) -> io::Result<()> {
        write_u16(self, value.to_be())
    }
    #[inline(always)]
    fn write_le_u16(&mut self, value: u16) -> io::Result<()> {
        write_u16(self, value.to_le())
    }

    #[inline(always)]
    fn write_be_u32(&mut self, value: u32) -> io::Result<()> {
        write_u32(self, value.to_be())
    }
    #[inline(always)]
    fn write_le_u32(&mut self, value: u32) -> io::Result<()> {
        write_u32(self, value.to_le())
    }

    #[inline(always)]
    fn write_be_u64(&mut self, value: u64) -> io::Result<()> {
        write_u64(self, value.to_be())
    }
    #[inline(always)]
    fn write_le_u64(&mut self, value: u64) -> io::Result<()> {
        write_u64(self, value.to_le())
    }
}

impl<W: Write> WriteExt for W {}

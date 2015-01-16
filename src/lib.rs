#![feature(slicing_syntax)]
#![crate_type = "lib"]
#![crate_name = "suruga"]
#![allow(missing_copy_implementations)]

#[macro_use]
extern crate log;

pub use tls::Tls;
pub use client::TlsClient;

#[macro_use]
pub mod macros;
pub mod util;

// basic crypto primitives
pub mod crypto {
    pub mod sha2;
    pub mod p256;
    pub mod poly1305;
    pub mod chacha20;
}

pub mod tls_result;
#[macro_use]
pub mod tls_item;
pub mod record;

// TLS AEAD cipehrsuites
pub mod cipher;

pub mod signature;
pub mod alert;
pub mod handshake;

pub mod tls;
pub mod client;

#[cfg(test)] mod test;

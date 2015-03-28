#![crate_type = "lib"]
#![crate_name = "suruga"]

#![feature(slice_bytes, slice_patterns)]

#[macro_use]
extern crate log;
extern crate rand;
extern crate num;

#[macro_use]
extern crate enum_primitive;
extern crate rustc_serialize; // base64
extern crate chrono;

pub use client::TlsClient;

#[macro_use]
pub mod macros;
pub mod util;

#[macro_use]
pub mod der;

// basic crypto primitives
pub mod crypto;

pub mod tls_result;
#[macro_use]
pub mod tls_item;

// TLS AEAD cipehrsuites
pub mod cipher;

pub mod signature;
pub mod alert;
pub mod handshake;

pub mod tls;
pub mod client;

#[macro_use]
pub mod x509;

#[cfg(test)] mod test;

suruga is Rust implementation of [TLS 1.2][tls-12].

It currently implements some core parts of TLS 1.2,
NIST P-256 [ECDHE][tls-ecc] and [chacha20-poly1305][tls-chacha20-poly1305].

# Usage

```Rust
extern crate suruga;

use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    test().unwrap();
}

fn test() -> suruga::tls_result::TlsResult<()> {
    let stream = try!(TcpStream::connect("www.google.com:443"));
    let mut client = try!(suruga::TlsClient::from_tcp(stream));
    let _len = try!(client.write(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"));

    let mut msg = vec![0u8; 100];
    try!(client.read(&mut msg));
    let msg = String::from_utf8_lossy(&msg);
    println!("msg: {}", msg);

    try!(client.close());

    Ok(())
}
```

[tls-12]: http://tools.ietf.org/html/rfc5246
[tls-ecc]: http://tools.ietf.org/html/rfc4492
[tls-chacha20-poly1305]: https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

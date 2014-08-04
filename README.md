suruga is Rust implementation of [TLS 1.2][tls-12].

It currently implements some core parts of TLS 1.2,
NIST P-256 [ECDHE][tls-ecc] and [chacha20-poly1305][tls-chacha20-poly1305].

# Usage

```Rust
extern crate suruga;

use std::io::net::tcp::TcpStream;

fn main() {
    let stream = TcpStream::connect("www.google.com", 443).unwrap();
    let mut client = suruga::TlsClient::from_tcp(stream).unwrap();
    client.write(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n").unwrap();
    let mut msg = Vec::from_elem(100, 0u8);
    client.read(msg.as_mut_slice()).unwrap();
    let msg = String::from_utf8_lossy(msg.as_slice());
    println!("msg: {}", msg);
    client.close().unwrap();
}
```

[tls-12]: http://tools.ietf.org/html/rfc5246
[tls-ecc]: http://tools.ietf.org/html/rfc4492
[tls-chacha20-poly1305]: https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

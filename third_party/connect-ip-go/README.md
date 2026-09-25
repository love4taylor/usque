# connect-ip-go compatibility port

This directory starts from `quic-go/connect-ip-go` master at `fdd945e3d6009b3cee1b1a66493776d315727549`.

The port keeps the upstream `Transport` / `ClientConn` API and adds the
Cloudflare behavior used by usque:

- custom CONNECT protocol and request headers;
- optional omission of the Extended CONNECT requirement;
- HTTP/2 CONNECT-IP datagram transport;
- zero-copy packet helpers used by the tunnel loop.

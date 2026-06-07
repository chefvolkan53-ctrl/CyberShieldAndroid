# Third-Party Notices

## CyberShield native VPN forwarder

`app/src/main/jniLibs/arm64-v8a/libcybershield_forwarder.so` is built from the Sockstun / hev-socks5-tunnel native userspace VPN forwarding stack and packaged as CyberShield's arm64-v8a native tun2socks engine.

Source project: https://github.com/heiher/sockstun

License: MIT

Copyright (c) 2023 hev

Copyright (c) 2022 hev

The native library is used to forward Android `VpnService` TUN traffic through a local SOCKS5 bridge, while CyberShield applies domain/IP/port blocking policy before protected outbound sockets are opened.

# wpa_supplicant

GOST-сборка выполняется из корня `wnam2-gost`:

```sh
make -C gost-eap-tls -j2 CC=gcc TLS=mbedtls test-wired
make -C gost-eap-tls -j2 CC=gcc TLS=openssl test-wired
make -C gost-eap-tls -j2 CC=musl-gcc TLS=mbedtls test-wired
make -C gost-eap-tls -j2 CC=musl-gcc TLS=openssl test-wired
```

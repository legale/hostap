# hostapd

GOST-сборка выполняется из корня `wnam2-gost`:

```sh
make -C gost-eap-tls -j2 TLS=mbedtls hostap
make -C gost-eap-tls -j2 TLS=openssl hostap
make -C gost-eap-tls hostap-cpro
```

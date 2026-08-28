# hostap

`hostapd` и `wpa_supplicant` с GOST TLS backend. В этом проекте они собираются
из корня `wnam2-gost`:

```sh
make -C gost-eap-tls -j2 TLS=mbedtls hostap
make -C gost-eap-tls -j2 TLS=openssl hostap
make -C gost-eap-tls hostap-cpro
```

Результаты находятся в `gost-eap-tls/build/hostap-*`.

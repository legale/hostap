# wpa_supplicant

Клиент Wi-Fi и wired 802.1X. Для GOST нужны `libnl`, выбранный TLS backend и
соответствующий `.config`.

```sh
cp defconfig .config
make -j2
```

Для CryptoPro нужен CryptoPro CSP, `lsb-cprocsp-devel` и glibc-компилятор.

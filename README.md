# hostap

`hostapd` и `wpa_supplicant` для 802.1X и WPA-Enterprise. Для GOST нужны
выбранный TLS backend, `libnl`, GOST-библиотека и соответствующий `.config`.

```sh
cd hostapd
cp defconfig .config
make -j2

cd ../wpa_supplicant
cp defconfig .config
make -j2
```

Для CryptoPro нужен CryptoPro CSP, `lsb-cprocsp-devel` и glibc-компилятор.

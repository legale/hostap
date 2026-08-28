# hostapd

Демон точки доступа и authenticator 802.1X. Для GOST нужны `libnl`, выбранный
TLS backend и соответствующий `.config`.

```sh
cp defconfig .config
make -j2
```

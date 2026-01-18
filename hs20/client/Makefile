ALL=hs20-osu-client

include ../../src/build.rules

CFLAGS += -I../../src/utils
CFLAGS += -I../../src/common
CFLAGS += -I../../src
CFLAGS += -DCONFIG_CRYPTO_INTERNAL

ifndef CONFIG_NO_BROWSER
ifndef CONFIG_BROWSER_SYSTEM
TEST_WK := $(shell pkg-config --silence-errors --cflags webkitgtk-3.0 2>/dev/null)
ifeq ($(TEST_WK),)
# Try webkit2
GTKCFLAGS := $(shell pkg-config --cflags gtk+-3.0 webkit2gtk-4.0 2>/dev/null)
GTKLIBS := $(shell pkg-config --libs gtk+-3.0 webkit2gtk-4.0 2>/dev/null)
ifneq ($(GTKCFLAGS),)
CFLAGS += -DUSE_WEBKIT2
CFLAGS += $(GTKCFLAGS)
LIBS += $(GTKLIBS)
else
# GTK not available, use browser-system instead
CONFIG_BROWSER_SYSTEM := y
endif
else
GTKCFLAGS := $(shell pkg-config --cflags gtk+-3.0 webkitgtk-3.0 2>/dev/null)
GTKLIBS := $(shell pkg-config --libs gtk+-3.0 webkitgtk-3.0 2>/dev/null)
ifneq ($(GTKCFLAGS),)
CFLAGS += $(GTKCFLAGS)
LIBS += $(GTKLIBS)
else
# GTK not available, use browser-system instead
CONFIG_BROWSER_SYSTEM := y
endif
endif
endif
endif

OBJS = osu_client.o
OBJS += ../../src/utils/xml-utils.o
CFLAGS += -DCONFIG_CTRL_IFACE
CFLAGS += -DCONFIG_CTRL_IFACE_UNIX
OBJS += ../../src/common/wpa_ctrl.o ../../src/common/wpa_helpers.o
ifdef CONFIG_NO_BROWSER
CFLAGS += -DCONFIG_NO_BROWSER
else
ifdef CONFIG_BROWSER_SYSTEM
OBJS += ../../src/utils/eloop.o
OBJS += ../../src/wps/httpread.o
OBJS += ../../src/wps/http_server.o
OBJS += ../../src/utils/browser-system.o
else
OBJS += ../../src/utils/browser.o
endif
endif
OBJS += ../../src/utils/xml_libxml2.o
OBJS += ../../src/utils/http_curl.o
OBJS += ../../src/utils/base64.o
OBJS += ../../src/utils/os_unix.o
CFLAGS += -DCONFIG_DEBUG_FILE
OBJS += ../../src/utils/wpa_debug.o
OBJS += ../../src/utils/common.o
OBJS += ../../src/utils/wpabuf.o
OBJS += ../../src/common/ieee802_11_common.o
OBJS += ../../src/common/wpa_common.o
OBJS += ../../src/crypto/crypto_internal.o
OBJS += ../../src/crypto/md5.o
OBJS += ../../src/crypto/md5-internal.o
OBJS += ../../src/crypto/sha1.o
OBJS += ../../src/crypto/sha1-internal.o
OBJS += ../../src/crypto/sha1-prf.o
OBJS += ../../src/crypto/sha256.o
OBJS += ../../src/crypto/sha256-internal.o
OBJS += ../../src/crypto/sha256-prf.o
OBJS += ../../src/crypto/aes-internal.o
OBJS += ../../src/crypto/aes-internal-enc.o
OBJS += ../../src/crypto/aes-internal-dec.o
OBJS += ../../src/crypto/aes-encblock.o
OBJS += ../../src/crypto/aes-wrap.o
OBJS += ../../src/crypto/aes-omac1.o

CFLAGS += $(shell xml2-config --cflags)
LIBS += $(shell xml2-config --libs)

# Allow static/custom linking of libcurl.
ifdef CUST_CURL_LINKAGE
LIBS += ${CUST_CURL_LINKAGE}
else
LIBS += -lcurl
endif

CFLAGS += -DEAP_TLS_OPENSSL
OBJS += ../../src/crypto/tls_openssl_ocsp.o
LIBS += -lssl -lcrypto

_OBJS_VAR := OBJS
include ../../src/objs.mk
hs20-osu-client: $(OBJS)
	$(Q)$(LDO) $(LDFLAGS) -o hs20-osu-client $(OBJS) $(LIBS)
	@$(E) "  LD " $@

clean: common-clean
	rm -f core *~

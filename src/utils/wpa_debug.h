/*
 * wpa_supplicant/hostapd / Debug prints
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_DEBUG_H
#define WPA_DEBUG_H

#include <time.h>
#include <string.h>

#include "wpabuf.h"
#include "common/ieee802_11_defs.h"

extern struct hapd_interfaces *global_ifaces;

extern void (*wpa_printf_hook)(int level, const char *fmt, va_list ap);
extern void (*wpa_hexdump_hook)(int level, const char *title,
				const void *buf, size_t len);
extern void (*wpa_netlink_hook)(int tx, const void *data, size_t len);
extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;
extern int wpa_debug_syslog;

/* Debugging function - conditional printf and hex dump. Driver wrappers can
 * use these for debugging purposes. */

enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR, MSG_WIFIMON
};

#ifdef CONFIG_NO_STDOUT_DEBUG

#define wpa_debug_print_timestamp() do { } while (0)
#define wpa_printf(args...) do { } while (0)
#define wpa_debug_open_file(p) do { } while (0)
#define wpa_debug_close_file() do { } while (0)
#define wpa_debug_setup_stdout() do { } while (0)
#define wpa_debug_stop_log() do { } while (0)
#define wpa_dbg(args...) do { } while (0)

static inline void wpa_hexdump(int level, const char *title,
			       const void *buf, size_t len)
{
}

static inline void wpa_hexdump_buf(int level, const char *title,
				   const struct wpabuf *buf)
{
}

static inline void wpa_hexdump_key(int level, const char *title,
				   const void *buf, size_t len)
{
}

static inline void wpa_hexdump_buf_key(int level, const char *title,
				       const struct wpabuf *buf)
{
}

static inline void wpa_hexdump_ascii(int level, const char *title,
				     const void *buf, size_t len)
{
}

static inline void wpa_hexdump_ascii_key(int level, const char *title,
					 const void *buf, size_t len)
{
}

static inline int wpa_debug_reopen_file(void)
{
	return 0;
}

#else /* CONFIG_NO_STDOUT_DEBUG */

int wpa_debug_open_file(const char *path);
int wpa_debug_reopen_file(void);
void wpa_debug_close_file(void);
void wpa_debug_setup_stdout(void);
void wpa_debug_stop_log(void);

/* internal */
void _wpa_hexdump(int level, const char *title, const u8 *buf,
		  size_t len, int show, int only_syslog);
void _wpa_hexdump_ascii(int level, const char *title, const void *buf,
			size_t len, int show);
extern int wpa_debug_show_keys;

#ifndef CONFIG_MSG_MIN_PRIORITY
#define CONFIG_MSG_MIN_PRIORITY 0
#endif

/**
 * wpa_debug_printf_timestamp - Print timestamp for debug output
 *
 * This function prints a timestamp in seconds_from_1970.microsoconds
 * format if debug output has been configured to include timestamps in debug
 * messages.
 */
void wpa_debug_print_timestamp(void);

void wpa_msg_glo(int level, const char *fmt, ...);

/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void _wpa_printf(int level, const char *fmt, ...)
PRINTF_FORMAT(2, 3);

#define wpa_printf(level, ...)						\
	do {								\
		if (level >= CONFIG_MSG_MIN_PRIORITY)			\
			_wpa_printf(level, __VA_ARGS__);		\
	} while(0)

/**
 * wpa_hexdump - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump.
 */
static inline void wpa_hexdump(int level, const char *title, const void *buf, size_t len)
{
	if (level < CONFIG_MSG_MIN_PRIORITY)
		return;

	_wpa_hexdump(level, title, buf, len, 1, 1);
}

static inline void wpa_hexdump_buf(int level, const char *title,
				   const struct wpabuf *buf)
{
	wpa_hexdump(level, title, buf ? wpabuf_head(buf) : NULL,
		    buf ? wpabuf_len(buf) : 0);
}

/**
 * wpa_hexdump_key - conditional hex dump, hide keys
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump. This works
 * like wpa_hexdump(), but by default, does not include secret keys (passwords,
 * etc.) in debug output.
 */
static inline void wpa_hexdump_key(int level, const char *title, const u8 *buf, size_t len)
{
	if (level < CONFIG_MSG_MIN_PRIORITY)
		return;

	_wpa_hexdump(level, title, buf, len, wpa_debug_show_keys, 1);
}

static inline void wpa_hexdump_buf_key(int level, const char *title,
				       const struct wpabuf *buf)
{
	wpa_hexdump_key(level, title, buf ? wpabuf_head(buf) : NULL,
			buf ? wpabuf_len(buf) : 0);
}

/**
 * wpa_hexdump_ascii - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump with both
 * the hex numbers and ASCII characters (for printable range) are shown. 16
 * bytes per line will be shown.
 */
static inline void wpa_hexdump_ascii(int level, const char *title,
				     const u8 *buf, size_t len)
{
	if (level < CONFIG_MSG_MIN_PRIORITY)
		return;

	_wpa_hexdump_ascii(level, title, buf, len, 1);
}

/**
 * wpa_hexdump_ascii_key - conditional hex dump, hide keys
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump with both
 * the hex numbers and ASCII characters (for printable range) are shown. 16
 * bytes per line will be shown. This works like wpa_hexdump_ascii(), but by
 * default, does not include secret keys (passwords, etc.) in debug output.
 */
static inline void wpa_hexdump_ascii_key(int level, const char *title,
					 const u8 *buf, size_t len)
{
	if (level < CONFIG_MSG_MIN_PRIORITY)
		return;

	_wpa_hexdump_ascii(level, title, buf, len, wpa_debug_show_keys);
}

/*
 * wpa_dbg() behaves like wpa_msg(), but it can be removed from build to reduce
 * binary size. As such, it should be used with debugging messages that are not
 * needed in the control interface while wpa_msg() has to be used for anything
 * that needs to shown to control interface monitors.
 */
#define wpa_dbg(args...) wpa_msg(args)

#endif /* CONFIG_NO_STDOUT_DEBUG */


#ifdef CONFIG_NO_WPA_MSG
#define wpa_msg(args...) do { } while (0)
#define wpa_msg_ctrl(args...) do { } while (0)
#define wpa_msg_global(args...) do { } while (0)
#define wpa_msg_global_ctrl(args...) do { } while (0)
#define wpa_msg_no_global(args...) do { } while (0)
#define wpa_msg_global_only(args...) do { } while (0)
#define wpa_msg_register_cb(f) do { } while (0)
#define wpa_msg_register_ifname_cb(f) do { } while (0)
#else /* CONFIG_NO_WPA_MSG */
/**
 * wpa_msg - Conditional printf for default target and ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. This function is like wpa_printf(), but it also sends the
 * same message to all attached ctrl_iface monitors.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void _wpa_msg(void *ctx, int level, const char *fmt, ...) PRINTF_FORMAT(3, 4);
#define wpa_msg(ctx, level, ...)					\
	do {								\
		if (level >= CONFIG_MSG_MIN_PRIORITY)			\
			_wpa_msg(ctx, level, __VA_ARGS__);		\
	} while(0)

/**
 * wpa_msg_ctrl - Conditional printf for ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages.
 * This function is like wpa_msg(), but it sends the output only to the
 * attached ctrl_iface monitors. In other words, it can be used for frequent
 * events that do not need to be sent to syslog.
 */
void _wpa_msg_ctrl(void *ctx, int level, const char *fmt, ...)
PRINTF_FORMAT(3, 4);
#define wpa_msg_ctrl(ctx, level, ...)					\
	do {								\
		if (level >= CONFIG_MSG_MIN_PRIORITY)			\
			_wpa_msg_ctrl(ctx, level, __VA_ARGS__);		\
	} while(0)

/**
 * wpa_msg_global - Global printf for ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages.
 * This function is like wpa_msg(), but it sends the output as a global event,
 * i.e., without being specific to an interface. For backwards compatibility,
 * an old style event is also delivered on one of the interfaces (the one
 * specified by the context data).
 */
void wpa_msg_global(void *ctx, int level, const char *fmt, ...)
PRINTF_FORMAT(3, 4);

/**
 * wpa_msg_global_ctrl - Conditional global printf for ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages.
 * This function is like wpa_msg_global(), but it sends the output only to the
 * attached global ctrl_iface monitors. In other words, it can be used for
 * frequent events that do not need to be sent to syslog.
 */
void wpa_msg_global_ctrl(void *ctx, int level, const char *fmt, ...)
PRINTF_FORMAT(3, 4);

/**
 * wpa_msg_no_global - Conditional printf for ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages.
 * This function is like wpa_msg(), but it does not send the output as a global
 * event.
 */
void wpa_msg_no_global(void *ctx, int level, const char *fmt, ...)
PRINTF_FORMAT(3, 4);

/**
 * wpa_msg_global_only - Conditional printf for ctrl_iface monitors
 * @ctx: Pointer to context data; this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages.
 * This function is like wpa_msg_global(), but it sends the output only as a
 * global event.
 */
void wpa_msg_global_only(void *ctx, int level, const char *fmt, ...)
PRINTF_FORMAT(3, 4);

enum wpa_msg_type {
	WPA_MSG_PER_INTERFACE,
	WPA_MSG_GLOBAL,
	WPA_MSG_NO_GLOBAL,
	WPA_MSG_ONLY_GLOBAL,
};

typedef void (*wpa_msg_cb_func)(void *ctx, int level, enum wpa_msg_type type,
				const char *txt, size_t len);

/**
 * wpa_msg_register_cb - Register callback function for wpa_msg() messages
 * @func: Callback function (%NULL to unregister)
 */
void wpa_msg_register_cb(wpa_msg_cb_func func);

typedef const char * (*wpa_msg_get_ifname_func)(void *ctx);
void wpa_msg_register_ifname_cb(wpa_msg_get_ifname_func func);

#endif /* CONFIG_NO_WPA_MSG */

#ifdef CONFIG_NO_HOSTAPD_LOGGER
#define hostapd_logger(args...) do { } while (0)
#define hostapd_logger_register_cb(f) do { } while (0)
#else /* CONFIG_NO_HOSTAPD_LOGGER */
void hostapd_logger(void *ctx, const u8 *addr, unsigned int module, int level,
		    const char *fmt, ...) PRINTF_FORMAT(5, 6);

typedef void (*hostapd_logger_cb_func)(void *ctx, const u8 *addr,
				       unsigned int module, int level,
				       const char *txt, size_t len);

/**
 * hostapd_logger_register_cb - Register callback function for hostapd_logger()
 * @func: Callback function (%NULL to unregister)
 */
void hostapd_logger_register_cb(hostapd_logger_cb_func func);
#endif /* CONFIG_NO_HOSTAPD_LOGGER */

#define HOSTAPD_MODULE_IEEE80211	0x00000001
#define HOSTAPD_MODULE_IEEE8021X	0x00000002
#define HOSTAPD_MODULE_RADIUS		0x00000004
#define HOSTAPD_MODULE_WPA		0x00000008
#define HOSTAPD_MODULE_DRIVER		0x00000010
#define HOSTAPD_MODULE_MLME		0x00000040

enum hostapd_logger_level {
	HOSTAPD_LEVEL_DEBUG_VERBOSE = 0,
	HOSTAPD_LEVEL_DEBUG = 1,
	HOSTAPD_LEVEL_INFO = 2,
	HOSTAPD_LEVEL_NOTICE = 3,
	HOSTAPD_LEVEL_WARNING = 4
};


#ifdef CONFIG_DEBUG_SYSLOG

void wpa_debug_open_syslog(void);
void wpa_debug_close_syslog(void);

#else /* CONFIG_DEBUG_SYSLOG */

static inline void wpa_debug_open_syslog(void)
{
}

static inline void wpa_debug_close_syslog(void)
{
}

#endif /* CONFIG_DEBUG_SYSLOG */

#ifdef CONFIG_DEBUG_LINUX_TRACING

int wpa_debug_open_linux_tracing(void);
void wpa_debug_close_linux_tracing(void);

#else /* CONFIG_DEBUG_LINUX_TRACING */

static inline int wpa_debug_open_linux_tracing(void)
{
	return 0;
}

static inline void wpa_debug_close_linux_tracing(void)
{
}

#endif /* CONFIG_DEBUG_LINUX_TRACING */


#ifdef EAPOL_TEST
#define WPA_ASSERT(a)						       \
	do {							       \
		if (!(a)) {					       \
			printf("WPA_ASSERT FAILED '" #a "' "	       \
			       "%s %s:%d\n",			       \
			       __FUNCTION__, __FILE__, __LINE__);      \
			exit(1);				       \
		}						       \
	} while (0)
#else
#define WPA_ASSERT(a) do { } while (0)
#endif

const char * debug_level_str(int level);
int str_to_debug_level(const char *s);

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

typedef enum wifi_stage {
	S_UNK = 0,                // unknown stage
	S_AUTH_REQ = 1,           // incoming mgmt::auth frame
	S_AUTH_HANDLE = 2,        // handle auth
	S_AUTH_HANDLE_RADIUS = 3, // handle auth RADIUS USE_EXTERNAL_RADIUS_AUTH
	S_AUTH_RES = 4,           // outgoing mgmt::auth frame
	S_ASSOC_REQ = 5,          // incoming mgmt::assoc frame
	S_ASSOC_RES = 6,          // outgoing mgmt::assoc frame
	S_RADIUS_AUTH_REQ = 7,    // radius req stage
	S_RADIUS_AUTH_RES = 8,    // radius resp stage
	S_HANDSHAKE = 9,          // handshake stage
	S_HANDSHAKE_DONE = 10,    // handshake done stage
	S_AUTHORIZED = 11,        // sta connected stage
	S_DEAUTHORIZED = 12,      // sta disconnected stage
	S_DEAUTH_REQ = 13,        // incoming mgmt:deauth frame
	S_DEAUTH_RES = 14,        // outgoing mgmt:deauth frame
	S_DISASSOC_REQ = 15,      // incoming mgmt::disassoc frame
	S_DISASSOC_RES = 16,      // outgoing mgmt::disassoc frame
	S_RADIUS_ACCT_REQ = 17,   // radius req acct stage
	S_RADIUS_ACCT_RES = 18,   // radius resp acct stage
	S_REASSOC_REQ = 19,       // incoming mgmt::reassoc frame
	S_REASSOC_RES = 20,       // outgoing mgmt::reassoc frame
	S_ACTIVE_SESSION = 21,    // active session stage (no corresponding tx/rx event)
} wifi_stage_t;

typedef enum wifimon_status {
	WIFIMON_OK = 0,
	WIFIMON_INF = 1,
	WIFIMON_ERR = 2,
	WIFIMON_WARN = 3,
} wifimon_status_t;

#define WMC_T_SC  0x1000u
#define WMC_T_RC  0x2000u

typedef enum wifimon_code {
	WMC_OK = 0,

	WMC_LOC_UNK = 1,
	WMC_LOC_LOCAL_DEAUTH_REQ = 2,
	WMC_LOC_INACTIVITY_DISASSOC = 3,
	WMC_LOC_INACTIVITY_DEAUTH = 4,
	WMC_LOC_DRV_LOST_STA = 5,
	WMC_LOC_FORCE_DEAUTH_NO_ASSOC = 6,
	WMC_LOC_AP_BUSY_KICK = 7,
	WMC_LOC_RADIUS_AUTH_FAIL = 8,
	WMC_LOC_RADIUS_ACCT_FAIL = 9,
	WMC_LOC_1X_AUTH_FAIL = 10,
	WMC_LOC_4WAY_TIMEOUT = 11,
	WMC_LOC_GTK_TIMEOUT = 12,
	WMC_LOC_MIC_FAILURE = 13,
	WMC_LOC_PTK_REKEY_FAIL = 14,
	WMC_LOC_GROUP_REKEY_FAIL = 15,

	WMC_SC_WLAN_STATUS_SUCCESS = (int)(WMC_T_SC + WLAN_STATUS_SUCCESS),
	WMC_SC_WLAN_STATUS_UNSPECIFIED_FAILURE = (int)(WMC_T_SC + WLAN_STATUS_UNSPECIFIED_FAILURE),
	WMC_SC_WLAN_STATUS_TDLS_WAKEUP_ALTERNATE = (int)(WMC_T_SC + WLAN_STATUS_TDLS_WAKEUP_ALTERNATE),
	WMC_SC_WLAN_STATUS_TDLS_WAKEUP_REJECT = (int)(WMC_T_SC + WLAN_STATUS_TDLS_WAKEUP_REJECT),
	WMC_SC_WLAN_STATUS_SECURITY_DISABLED = (int)(WMC_T_SC + WLAN_STATUS_SECURITY_DISABLED),
	WMC_SC_WLAN_STATUS_UNACCEPTABLE_LIFETIME = (int)(WMC_T_SC + WLAN_STATUS_UNACCEPTABLE_LIFETIME),
	WMC_SC_WLAN_STATUS_NOT_IN_SAME_BSS = (int)(WMC_T_SC + WLAN_STATUS_NOT_IN_SAME_BSS),
	WMC_SC_WLAN_STATUS_CAPS_UNSUPPORTED = (int)(WMC_T_SC + WLAN_STATUS_CAPS_UNSUPPORTED),
	WMC_SC_WLAN_STATUS_REASSOC_NO_ASSOC = (int)(WMC_T_SC + WLAN_STATUS_REASSOC_NO_ASSOC),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_UNSPEC = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_UNSPEC),
	WMC_SC_WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG = (int)(WMC_T_SC + WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG),
	WMC_SC_WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION = (int)(WMC_T_SC + WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION),
	WMC_SC_WLAN_STATUS_CHALLENGE_FAIL = (int)(WMC_T_SC + WLAN_STATUS_CHALLENGE_FAIL),
	WMC_SC_WLAN_STATUS_AUTH_TIMEOUT = (int)(WMC_T_SC + WLAN_STATUS_AUTH_TIMEOUT),
	WMC_SC_WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = (int)(WMC_T_SC + WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_RATES = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_RATES),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_NOSHORT = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NOSHORT),
	WMC_SC_WLAN_STATUS_SPEC_MGMT_REQUIRED = (int)(WMC_T_SC + WLAN_STATUS_SPEC_MGMT_REQUIRED),
	WMC_SC_WLAN_STATUS_PWR_CAPABILITY_NOT_VALID = (int)(WMC_T_SC + WLAN_STATUS_PWR_CAPABILITY_NOT_VALID),
	WMC_SC_WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID = (int)(WMC_T_SC + WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_SHORT_SLOT_TIME = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_SHORT_SLOT_TIME),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_HT = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_HT),
	WMC_SC_WLAN_STATUS_R0KH_UNREACHABLE = (int)(WMC_T_SC + WLAN_STATUS_R0KH_UNREACHABLE),
	WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_PCO = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_PCO),
	WMC_SC_WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY = (int)(WMC_T_SC + WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY),
	WMC_SC_WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION = (int)(WMC_T_SC + WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION),
	WMC_SC_WLAN_STATUS_UNSPECIFIED_QOS_FAILURE = (int)(WMC_T_SC + WLAN_STATUS_UNSPECIFIED_QOS_FAILURE),
	WMC_SC_WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH = (int)(WMC_T_SC + WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH),
	WMC_SC_WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS = (int)(WMC_T_SC + WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS),
	WMC_SC_WLAN_STATUS_DENIED_QOS_NOT_SUPPORTED = (int)(WMC_T_SC + WLAN_STATUS_DENIED_QOS_NOT_SUPPORTED),
	WMC_SC_WLAN_STATUS_REQUEST_DECLINED = (int)(WMC_T_SC + WLAN_STATUS_REQUEST_DECLINED),
	WMC_SC_WLAN_STATUS_INVALID_PARAMETERS = (int)(WMC_T_SC + WLAN_STATUS_INVALID_PARAMETERS),
	WMC_SC_WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES = (int)(WMC_T_SC + WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES),
	WMC_SC_WLAN_STATUS_INVALID_IE = (int)(WMC_T_SC + WLAN_STATUS_INVALID_IE),
	WMC_SC_WLAN_STATUS_GROUP_CIPHER_NOT_VALID = (int)(WMC_T_SC + WLAN_STATUS_GROUP_CIPHER_NOT_VALID),
	WMC_SC_WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID = (int)(WMC_T_SC + WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID),
	WMC_SC_WLAN_STATUS_AKMP_NOT_VALID = (int)(WMC_T_SC + WLAN_STATUS_AKMP_NOT_VALID),
	WMC_SC_WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION = (int)(WMC_T_SC + WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION),
	WMC_SC_WLAN_STATUS_INVALID_RSN_IE_CAPAB = (int)(WMC_T_SC + WLAN_STATUS_INVALID_RSN_IE_CAPAB),
	WMC_SC_WLAN_STATUS_CIPHER_REJECTED_PER_POLICY = (int)(WMC_T_SC + WLAN_STATUS_CIPHER_REJECTED_PER_POLICY),
	WMC_SC_WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT = (int)(WMC_T_SC + WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT),
	WMC_SC_WLAN_STATUS_INVALID_PMKID = (int)(WMC_T_SC + WLAN_STATUS_INVALID_PMKID),
	WMC_SC_WLAN_STATUS_INVALID_MDIE = (int)(WMC_T_SC + WLAN_STATUS_INVALID_MDIE),
	WMC_SC_WLAN_STATUS_INVALID_FTIE = (int)(WMC_T_SC + WLAN_STATUS_INVALID_FTIE),
	WMC_SC_WLAN_STATUS_TRY_ANOTHER_BSS = (int)(WMC_T_SC + WLAN_STATUS_TRY_ANOTHER_BSS),
	WMC_SC_WLAN_STATUS_TRANSMISSION_FAILURE = (int)(WMC_T_SC + WLAN_STATUS_TRANSMISSION_FAILURE),
	WMC_SC_WLAN_STATUS_REFUSED_EXTERNAL_REASON = (int)(WMC_T_SC + WLAN_STATUS_REFUSED_EXTERNAL_REASON),
	WMC_SC_WLAN_STATUS_REFUSED_AP_OUT_OF_MEMORY = (int)(WMC_T_SC + WLAN_STATUS_REFUSED_AP_OUT_OF_MEMORY),
	WMC_SC_WLAN_STATUS_FILS_AUTHENTICATION_FAILURE = (int)(WMC_T_SC + WLAN_STATUS_FILS_AUTHENTICATION_FAILURE),
	WMC_SC_WLAN_STATUS_UNKNOWN_AUTHENTICATION_SERVER = (int)(WMC_T_SC + WLAN_STATUS_UNKNOWN_AUTHENTICATION_SERVER),
	WMC_SC_WLAN_STATUS_DENIED_HE_NOT_SUPPORTED = (int)(WMC_T_SC + WLAN_STATUS_DENIED_HE_NOT_SUPPORTED),
	WMC_SC_WLAN_STATUS_SAE_HASH_TO_ELEMENT = (int)(WMC_T_SC + WLAN_STATUS_SAE_HASH_TO_ELEMENT),
	WMC_SC_WLAN_STATUS_SAE_PK = (int)(WMC_T_SC + WLAN_STATUS_SAE_PK),
	WMC_SC_WLAN_STATUS_OCI_MISMATCH = (int)(WMC_T_SC + WLAN_STATUS_OCI_MISMATCH),

	WMC_RC_WLAN_REASON_UNSPECIFIED = (int)(WMC_T_RC + WLAN_REASON_UNSPECIFIED),
	WMC_RC_WLAN_REASON_PREV_AUTH_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_PREV_AUTH_NOT_VALID),
	WMC_RC_WLAN_REASON_DEAUTH_LEAVING = (int)(WMC_T_RC + WLAN_REASON_DEAUTH_LEAVING),
	WMC_RC_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = (int)(WMC_T_RC + WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY),
	WMC_RC_WLAN_REASON_DISASSOC_AP_BUSY = (int)(WMC_T_RC + WLAN_REASON_DISASSOC_AP_BUSY),
	WMC_RC_WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = (int)(WMC_T_RC + WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA),
	WMC_RC_WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = (int)(WMC_T_RC + WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA),
	WMC_RC_WLAN_REASON_DISASSOC_STA_HAS_LEFT = (int)(WMC_T_RC + WLAN_REASON_DISASSOC_STA_HAS_LEFT),
	WMC_RC_WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = (int)(WMC_T_RC + WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH),
	WMC_RC_WLAN_REASON_PWR_CAPABILITY_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_PWR_CAPABILITY_NOT_VALID),
	WMC_RC_WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID),
	WMC_RC_WLAN_REASON_BSS_TRANSITION_DISASSOC = (int)(WMC_T_RC + WLAN_REASON_BSS_TRANSITION_DISASSOC),
	WMC_RC_WLAN_REASON_INVALID_IE = (int)(WMC_T_RC + WLAN_REASON_INVALID_IE),
	WMC_RC_WLAN_REASON_MICHAEL_MIC_FAILURE = (int)(WMC_T_RC + WLAN_REASON_MICHAEL_MIC_FAILURE),
	WMC_RC_WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT = (int)(WMC_T_RC + WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT),
	WMC_RC_WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT = (int)(WMC_T_RC + WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT),
	WMC_RC_WLAN_REASON_IE_IN_4WAY_DIFFERS = (int)(WMC_T_RC + WLAN_REASON_IE_IN_4WAY_DIFFERS),
	WMC_RC_WLAN_REASON_GROUP_CIPHER_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_GROUP_CIPHER_NOT_VALID),
	WMC_RC_WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID),
	WMC_RC_WLAN_REASON_AKMP_NOT_VALID = (int)(WMC_T_RC + WLAN_REASON_AKMP_NOT_VALID),
	WMC_RC_WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION = (int)(WMC_T_RC + WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION),
	WMC_RC_WLAN_REASON_INVALID_RSN_IE_CAPAB = (int)(WMC_T_RC + WLAN_REASON_INVALID_RSN_IE_CAPAB),
	WMC_RC_WLAN_REASON_IEEE_802_1X_AUTH_FAILED = (int)(WMC_T_RC + WLAN_REASON_IEEE_802_1X_AUTH_FAILED),
	WMC_RC_WLAN_REASON_CIPHER_SUITE_REJECTED = (int)(WMC_T_RC + WLAN_REASON_CIPHER_SUITE_REJECTED),
	WMC_RC_WLAN_REASON_BAD_CIPHER_OR_AKM = (int)(WMC_T_RC + WLAN_REASON_BAD_CIPHER_OR_AKM),
	WMC_RC_WLAN_REASON_NOT_AUTHORIZED_THIS_LOCATION = (int)(WMC_T_RC + WLAN_REASON_NOT_AUTHORIZED_THIS_LOCATION),
	WMC_RC_WLAN_REASON_DISASSOC_LOW_ACK = (int)(WMC_T_RC + WLAN_REASON_DISASSOC_LOW_ACK),
	WMC_RC_WLAN_REASON_TIMEOUT = (int)(WMC_T_RC + WLAN_REASON_TIMEOUT),
} wifimon_code_t;

/* helper: choose wifimon_code from sc/rc while still allowing local override */
static inline wifimon_code_t wifimon_code_from_status(int sc)
{
	return (wifimon_code_t)(1000 + sc);
}

static inline wifimon_code_t wifimon_code_from_reason(int rc)
{
	return (wifimon_code_t)(2000 + rc);
}

void wpa_msg_glo(int level, const char *fmt, ...);
void debug_print_rsn_ie(const u8 *pos, size_t left, const u8 *mac, const u8 *bssid);

// Макрос для сообщений wifimon с разным статусом
#define WIFIMON_MSG(wifimon_status, stage, fmt, ...) \
	wpa_msg_glo(MSG_WIFIMON, "%s:%d: %s: wifimon_status=%d stage=%d " fmt, __FILENAME__, __LINE__, __FUNCTION__, wifimon_status, stage, ##__VA_ARGS__)

#define WIFIMON_OK(stage, fmt, ...) WIFIMON_MSG(WIFIMON_OK, stage, fmt, ##__VA_ARGS__)
#define WIFIMON_INF(stage, fmt, ...) WIFIMON_MSG(WIFIMON_INF, stage, fmt, ##__VA_ARGS__)
#define WIFIMON_ERR(stage, fmt, ...) WIFIMON_MSG(WIFIMON_ERR, stage, fmt, ##__VA_ARGS__)
#define WIFIMON_WARN(stage, fmt, ...) WIFIMON_MSG(WIFIMON_WARN, stage, fmt, ##__VA_ARGS__)
#define WIFIMON_DEBUG(stage, fmt, ...) WIFIMON_MSG(WIFIMON_INF, stage, fmt, ##__VA_ARGS__)

#endif /* WPA_DEBUG_H */

/*
 * wpa_supplicant/hostapd / Debug prints
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

 #include <time.h>

 #include "includes.h"
 
 #include "common.h"
 
 #include "../ap/hostapd.h"
 #include "common/ctrl_iface_common.h"


#ifdef CONFIG_DEBUG_SYSLOG
#include <syslog.h>
#endif /* CONFIG_DEBUG_SYSLOG */

#ifdef CONFIG_DEBUG_LINUX_TRACING
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

static FILE *wpa_debug_tracing_file = NULL;

#define WPAS_TRACE_PFX "wpas <%d>: "
#endif /* CONFIG_DEBUG_LINUX_TRACING */


int wpa_debug_level = MSG_INFO;
int wpa_debug_show_keys = 0;
int wpa_debug_timestamp = 0;
int wpa_debug_syslog = 0;
#ifndef CONFIG_NO_STDOUT_DEBUG
static FILE *out_file = NULL;
#endif /* CONFIG_NO_STDOUT_DEBUG */


#ifdef CONFIG_ANDROID_LOG

#include <android/log.h>

#ifndef ANDROID_LOG_NAME
#define ANDROID_LOG_NAME	"wpa_supplicant"
#endif /* ANDROID_LOG_NAME */

static int wpa_to_android_level(int level)
{
	if (level == MSG_ERROR)
		return ANDROID_LOG_ERROR;
	if (level == MSG_WARNING)
		return ANDROID_LOG_WARN;
	if (level == MSG_INFO)
		return ANDROID_LOG_INFO;
	return ANDROID_LOG_DEBUG;
}

#endif /* CONFIG_ANDROID_LOG */

#ifndef CONFIG_NO_STDOUT_DEBUG

#ifdef CONFIG_DEBUG_FILE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif /* CONFIG_DEBUG_FILE */


void wpa_debug_print_timestamp(void)
{
#ifndef CONFIG_ANDROID_LOG
	struct os_time tv;

	if (!wpa_debug_timestamp)
		return;

	os_get_time(&tv);
#ifdef CONFIG_DEBUG_FILE
	if (out_file)
		fprintf(out_file, "%ld.%06u: ", (long) tv.sec,
			(unsigned int) tv.usec);
#endif /* CONFIG_DEBUG_FILE */
	if (!out_file && !wpa_debug_syslog)
		printf("%ld.%06u: ", (long) tv.sec, (unsigned int) tv.usec);
#endif /* CONFIG_ANDROID_LOG */
}


#ifdef CONFIG_DEBUG_SYSLOG
#ifndef LOG_HOSTAPD
#define LOG_HOSTAPD LOG_DAEMON
#endif /* LOG_HOSTAPD */

void wpa_debug_open_syslog(void)
{
	openlog("wpa_supplicant", LOG_PID | LOG_NDELAY, LOG_HOSTAPD);
	wpa_debug_syslog++;
}


void wpa_debug_close_syslog(void)
{
	if (wpa_debug_syslog)
		closelog();
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
	case MSG_DEBUG:
		return LOG_DEBUG;
	case MSG_INFO:
		return LOG_NOTICE;
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_INFO;
}
#endif /* CONFIG_DEBUG_SYSLOG */


#ifdef CONFIG_DEBUG_LINUX_TRACING

int wpa_debug_open_linux_tracing(void)
{
	int mounts, trace_fd;
	char buf[4096] = {};
	ssize_t buflen;
	char *line, *tmp1, *path = NULL;

	mounts = open("/proc/mounts", O_RDONLY);
	if (mounts < 0) {
		printf("no /proc/mounts\n");
		return -1;
	}

	buflen = read(mounts, buf, sizeof(buf) - 1);
	close(mounts);
	if (buflen < 0) {
		printf("failed to read /proc/mounts\n");
		return -1;
	}
	buf[buflen] = '\0';

	line = strtok_r(buf, "\n", &tmp1);
	while (line) {
		char *tmp2, *tmp_path, *fstype;
		/* "<dev> <mountpoint> <fs type> ..." */
		strtok_r(line, " ", &tmp2);
		tmp_path = strtok_r(NULL, " ", &tmp2);
		fstype = strtok_r(NULL, " ", &tmp2);
		if (fstype && strcmp(fstype, "debugfs") == 0) {
			path = tmp_path;
			break;
		}

		line = strtok_r(NULL, "\n", &tmp1);
	}

	if (path == NULL) {
		printf("debugfs mountpoint not found\n");
		return -1;
	}

	snprintf(buf, sizeof(buf) - 1, "%s/tracing/trace_marker", path);

	trace_fd = open(buf, O_WRONLY);
	if (trace_fd < 0) {
		printf("failed to open trace_marker file\n");
		return -1;
	}
	wpa_debug_tracing_file = fdopen(trace_fd, "w");
	if (wpa_debug_tracing_file == NULL) {
		close(trace_fd);
		printf("failed to fdopen()\n");
		return -1;
	}

	return 0;
}


void wpa_debug_close_linux_tracing(void)
{
	if (wpa_debug_tracing_file == NULL)
		return;
	fclose(wpa_debug_tracing_file);
	wpa_debug_tracing_file = NULL;
}

#endif /* CONFIG_DEBUG_LINUX_TRACING */

struct hapd_interfaces *global_ifaces = NULL;

void wpa_msg_glo(int level, const char *fmt, ...)
{
    if (!global_ifaces || global_ifaces->global_ctrl_sock == -1 || 
        dl_list_empty(&global_ifaces->global_ctrl_dst)) {
        return;
    }

    // Формируем сообщение
    va_list ap;
    va_start(ap, fmt);
    char msg[1024];
    int len = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (len < 0 || len >= sizeof(msg)) return;

    // Добавляем временную метку
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) return;

    char buf[1088];
    int buflen = snprintf(buf, sizeof(buf), "IFNAME=GLOBAL <%d>%s ts=%ld.%09ld",
                         level, msg, (long)ts.tv_sec, ts.tv_nsec);
    if (buflen < 0 || buflen >= sizeof(buf)) return;

    // Подготовка сообщения
    struct iovec io[1] = {
        { .iov_base = buf, .iov_len = buflen }
    };

    struct msghdr hdr = {
        .msg_iov = io,
        .msg_iovlen = 1,
    };

    // Отправка всем подписчикам
    struct wpa_ctrl_dst *dst, *next;
    dl_list_for_each_safe(dst, next, &global_ifaces->global_ctrl_dst, 
                         struct wpa_ctrl_dst, list) {
        if (level >= dst->debug_level) {
            hdr.msg_name = &dst->addr;
            hdr.msg_namelen = dst->addrlen;
            
            if (sendmsg(global_ifaces->global_ctrl_sock, &hdr, MSG_NOSIGNAL) < 0) {
                if (errno == ENOENT || dst->errors++ > 10) {
                    dl_list_del(&dst->list);
                    os_free(dst);
                }
            } else {
                dst->errors = 0;
            }
        }
    }
}

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
void wpa_printf(int level, const char *fmt, ...)
{
	va_list ap;

	if (level >= wpa_debug_level) {
#ifdef CONFIG_ANDROID_LOG
		va_start(ap, fmt);
		__android_log_vprint(wpa_to_android_level(level),
				     ANDROID_LOG_NAME, fmt, ap);
		va_end(ap);
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
		if (wpa_debug_syslog) {
			va_start(ap, fmt);
			vsyslog(syslog_priority(level), fmt, ap);
			va_end(ap);
		}
#endif /* CONFIG_DEBUG_SYSLOG */
		wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
		if (out_file) {
			va_start(ap, fmt);
			vfprintf(out_file, fmt, ap);
			fprintf(out_file, "\n");
			va_end(ap);
		}
#endif /* CONFIG_DEBUG_FILE */
		if (!wpa_debug_syslog && !out_file) {
			va_start(ap, fmt);
			vprintf(fmt, ap);
			printf("\n");
			va_end(ap);
		}
#endif /* CONFIG_ANDROID_LOG */
	}

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		va_start(ap, fmt);
		fprintf(wpa_debug_tracing_file, WPAS_TRACE_PFX, level);
		vfprintf(wpa_debug_tracing_file, fmt, ap);
		fprintf(wpa_debug_tracing_file, "\n");
		fflush(wpa_debug_tracing_file);
		va_end(ap);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */
}


static void _wpa_hexdump(int level, const char *title, const u8 *buf,
			 size_t len, int show, int only_syslog)
{
	size_t i;

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		fprintf(wpa_debug_tracing_file,
			WPAS_TRACE_PFX "%s - hexdump(len=%lu):",
			level, title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(wpa_debug_tracing_file, " [NULL]\n");
		} else if (!show) {
			fprintf(wpa_debug_tracing_file, " [REMOVED]\n");
		} else {
			for (i = 0; i < len; i++)
				fprintf(wpa_debug_tracing_file,
					" %02x", buf[i]);
		}
		fflush(wpa_debug_tracing_file);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */

	if (level < wpa_debug_level)
		return;
#ifdef CONFIG_ANDROID_LOG
	{
		const char *display;
		char *strbuf = NULL;
		size_t slen = len;
		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			/* Limit debug message length for Android log */
			if (slen > 32)
				slen = 32;
			strbuf = os_malloc(1 + 3 * slen);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < slen; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		__android_log_print(wpa_to_android_level(level),
				    ANDROID_LOG_NAME,
				    "%s - hexdump(len=%lu):%s%s",
				    title, (long unsigned int) len, display,
				    len > slen ? " ..." : "");
		bin_clear_free(strbuf, 1 + 3 * slen);
		return;
	}
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
	if (wpa_debug_syslog) {
		const char *display;
		char *strbuf = NULL;

		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			strbuf = os_malloc(1 + 3 * len);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < len; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		syslog(syslog_priority(level), "%s - hexdump(len=%lu):%s",
		       title, (unsigned long) len, display);
		bin_clear_free(strbuf, 1 + 3 * len);
		if (only_syslog)
			return;
	}
#endif /* CONFIG_DEBUG_SYSLOG */
	wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
	if (out_file) {
		fprintf(out_file, "%s - hexdump(len=%lu):",
			title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(out_file, " [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				fprintf(out_file, " %02x", buf[i]);
		} else {
			fprintf(out_file, " [REMOVED]");
		}
		fprintf(out_file, "\n");
	}
#endif /* CONFIG_DEBUG_FILE */
	if (!wpa_debug_syslog && !out_file) {
		printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
		if (buf == NULL) {
			printf(" [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				printf(" %02x", buf[i]);
		} else {
			printf(" [REMOVED]");
		}
		printf("\n");
	}
#endif /* CONFIG_ANDROID_LOG */
}

void wpa_hexdump(int level, const char *title, const void *buf, size_t len)
{
	_wpa_hexdump(level, title, buf, len, 1, 0);
}


void wpa_hexdump_key(int level, const char *title, const void *buf, size_t len)
{
	_wpa_hexdump(level, title, buf, len, wpa_debug_show_keys, 0);
}


static void _wpa_hexdump_ascii(int level, const char *title, const void *buf,
			       size_t len, int show)
{
	size_t i, llen;
	const u8 *pos = buf;
	const size_t line_len = 16;

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		fprintf(wpa_debug_tracing_file,
			WPAS_TRACE_PFX "%s - hexdump_ascii(len=%lu):",
			level, title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(wpa_debug_tracing_file, " [NULL]\n");
		} else if (!show) {
			fprintf(wpa_debug_tracing_file, " [REMOVED]\n");
		} else {
			/* can do ascii processing in userspace */
			for (i = 0; i < len; i++)
				fprintf(wpa_debug_tracing_file,
					" %02x", pos[i]);
		}
		fflush(wpa_debug_tracing_file);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */

	if (level < wpa_debug_level)
		return;
#ifdef CONFIG_ANDROID_LOG
	_wpa_hexdump(level, title, buf, len, show, 0);
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
	if (wpa_debug_syslog)
		_wpa_hexdump(level, title, buf, len, show, 1);
#endif /* CONFIG_DEBUG_SYSLOG */
	wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
	if (out_file) {
		if (!show) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			goto file_done;
		}
		if (buf == NULL) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			goto file_done;
		}
		fprintf(out_file, "%s - hexdump_ascii(len=%lu):\n",
			title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			fprintf(out_file, "    ");
			for (i = 0; i < llen; i++)
				fprintf(out_file, " %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				fprintf(out_file, "   ");
			fprintf(out_file, "   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					fprintf(out_file, "%c", pos[i]);
				else
					fprintf(out_file, "_");
			}
			for (i = llen; i < line_len; i++)
				fprintf(out_file, " ");
			fprintf(out_file, "\n");
			pos += llen;
			len -= llen;
		}
	}
file_done:
#endif /* CONFIG_DEBUG_FILE */
	if (!wpa_debug_syslog && !out_file) {
		if (!show) {
			printf("%s - hexdump_ascii(len=%lu): [REMOVED]\n",
			       title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
			       title, (unsigned long) len);
			return;
		}
		printf("%s - hexdump_ascii(len=%lu):\n", title,
		       (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			printf("    ");
			for (i = 0; i < llen; i++)
				printf(" %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				printf("   ");
			printf("   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					printf("%c", pos[i]);
				else
					printf("_");
			}
			for (i = llen; i < line_len; i++)
				printf(" ");
			printf("\n");
			pos += llen;
			len -= llen;
		}
	}
#endif /* CONFIG_ANDROID_LOG */
}


void wpa_hexdump_ascii(int level, const char *title, const void *buf,
		       size_t len)
{
	_wpa_hexdump_ascii(level, title, buf, len, 1);
}


void wpa_hexdump_ascii_key(int level, const char *title, const void *buf,
			   size_t len)
{
	_wpa_hexdump_ascii(level, title, buf, len, wpa_debug_show_keys);
}


#ifdef CONFIG_DEBUG_FILE
static char *last_path = NULL;
#endif /* CONFIG_DEBUG_FILE */

int wpa_debug_reopen_file(void)
{
#ifdef CONFIG_DEBUG_FILE
	int rv;
	char *tmp;

	if (!last_path)
		return 0; /* logfile not used */

	tmp = os_strdup(last_path);
	if (!tmp)
		return -1;

	wpa_debug_close_file();
	rv = wpa_debug_open_file(tmp);
	os_free(tmp);
	return rv;
#else /* CONFIG_DEBUG_FILE */
	return 0;
#endif /* CONFIG_DEBUG_FILE */
}


int wpa_debug_open_file(const char *path)
{
#ifdef CONFIG_DEBUG_FILE
	int out_fd;

	if (!path)
		return 0;

	if (last_path == NULL || os_strcmp(last_path, path) != 0) {
		/* Save our path to enable re-open */
		os_free(last_path);
		last_path = os_strdup(path);
	}

	out_fd = open(path, O_CREAT | O_APPEND | O_WRONLY,
		      S_IRUSR | S_IWUSR | S_IRGRP);
	if (out_fd < 0) {
		wpa_printf(MSG_ERROR,
			   "%s: Failed to open output file descriptor, using standard output",
			   __func__);
		return -1;
	}

#ifdef __linux__
	if (fcntl(out_fd, F_SETFD, FD_CLOEXEC) < 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Failed to set FD_CLOEXEC - continue without: %s",
			   __func__, strerror(errno));
	}
#endif /* __linux__ */

	out_file = fdopen(out_fd, "a");
	if (out_file == NULL) {
		wpa_printf(MSG_ERROR, "wpa_debug_open_file: Failed to open "
			   "output file, using standard output");
		close(out_fd);
		return -1;
	}
#ifndef _WIN32
	setvbuf(out_file, NULL, _IOLBF, 0);
#endif /* _WIN32 */
#else /* CONFIG_DEBUG_FILE */
	(void)path;
#endif /* CONFIG_DEBUG_FILE */
	return 0;
}


void wpa_debug_close_file(void)
{
#ifdef CONFIG_DEBUG_FILE
	if (!out_file)
		return;
	fclose(out_file);
	out_file = NULL;
	os_free(last_path);
	last_path = NULL;
#endif /* CONFIG_DEBUG_FILE */
}


void wpa_debug_setup_stdout(void)
{
#ifndef _WIN32
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif /* _WIN32 */
}

#endif /* CONFIG_NO_STDOUT_DEBUG */


#ifndef CONFIG_NO_WPA_MSG
static wpa_msg_cb_func wpa_msg_cb = NULL;

void wpa_msg_register_cb(wpa_msg_cb_func func)
{
	wpa_msg_cb = func;
}


static wpa_msg_get_ifname_func wpa_msg_ifname_cb = NULL;

void wpa_msg_register_ifname_cb(wpa_msg_get_ifname_func func)
{
	wpa_msg_ifname_cb = func;
}


void wpa_msg(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;
	char prefix[130];

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg: Failed to allocate message "
			   "buffer");
		return;
	}
	va_start(ap, fmt);
	prefix[0] = '\0';
	if (wpa_msg_ifname_cb) {
		const char *ifname = wpa_msg_ifname_cb(ctx);
		if (ifname) {
			int res = os_snprintf(prefix, sizeof(prefix), "%s: ",
					      ifname);
			if (os_snprintf_error(sizeof(prefix), res))
				prefix[0] = '\0';
		}
	}
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s%s", prefix, buf);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_PER_INTERFACE, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_ctrl(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	if (!wpa_msg_cb)
		return;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_ctrl: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_msg_cb(ctx, level, WPA_MSG_PER_INTERFACE, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_global: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", buf);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global_ctrl(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	if (!wpa_msg_cb)
		return;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "wpa_msg_global_ctrl: Failed to allocate message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_msg_cb(ctx, level, WPA_MSG_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_no_global(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_no_global: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", buf);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_NO_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global_only(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "%s: Failed to allocate message buffer",
			   __func__);
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", buf);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_ONLY_GLOBAL, buf, len);
	os_free(buf);
}

#endif /* CONFIG_NO_WPA_MSG */


#ifndef CONFIG_NO_HOSTAPD_LOGGER
static hostapd_logger_cb_func hostapd_logger_cb = NULL;

void hostapd_logger_register_cb(hostapd_logger_cb_func func)
{
	hostapd_logger_cb = func;
}


void hostapd_logger(void *ctx, const u8 *addr, unsigned int module, int level,
		    const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "hostapd_logger: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (hostapd_logger_cb)
		hostapd_logger_cb(ctx, addr, module, level, buf, len);
	else if (addr)
		wpa_printf(MSG_DEBUG, "hostapd_logger: STA " MACSTR " - %s",
			   MAC2STR(addr), buf);
	else
		wpa_printf(MSG_DEBUG, "hostapd_logger: %s", buf);
	bin_clear_free(buf, buflen);
}
#endif /* CONFIG_NO_HOSTAPD_LOGGER */


const char * debug_level_str(int level)
{
	switch (level) {
	case MSG_EXCESSIVE:
		return "EXCESSIVE";
	case MSG_MSGDUMP:
		return "MSGDUMP";
	case MSG_DEBUG:
		return "DEBUG";
	case MSG_INFO:
		return "INFO";
	case MSG_WARNING:
		return "WARNING";
	case MSG_ERROR:
		return "ERROR";
	default:
		return "?";
	}
}


int str_to_debug_level(const char *s)
{
	if (os_strcasecmp(s, "EXCESSIVE") == 0)
		return MSG_EXCESSIVE;
	if (os_strcasecmp(s, "MSGDUMP") == 0)
		return MSG_MSGDUMP;
	if (os_strcasecmp(s, "DEBUG") == 0)
		return MSG_DEBUG;
	if (os_strcasecmp(s, "INFO") == 0)
		return MSG_INFO;
	if (os_strcasecmp(s, "WARNING") == 0)
		return MSG_WARNING;
	if (os_strcasecmp(s, "ERROR") == 0)
		return MSG_ERROR;
	return -1;
}

/**
 * debug_print_rsn_ie - Выводит информацию об RSN IE в одну строку
 * @pos: Указатель на начало буфера с IE
 * @left: Размер оставшейся части буфера
 * @sta_addr: MAC-адрес станции (для логирования)
 */
void debug_print_rsn_ie(const u8 *pos, size_t left, const u8 *mac, const u8 *bssid)
{
    const u8 *rsn_ie = NULL;
    size_t rsn_ie_len = 0;
    struct wpa_ie_data rsn_data;
    char group_name[32] = "unk";
    char pairwise_name[32] = "unk";
    char key_mgmt_name[256] = {0};
    char mgmt_group_name[32] = "unk";
    
    rsn_ie = get_ie(pos, left, WLAN_EID_RSN);
    if (!rsn_ie || rsn_ie[1] == 0) {
        WIFIMON_DEBUG(S_AUTH_HANDLE, "RSN IE not found for mac="MACSTR " bssid=" MACSTR, MAC2STR(mac), MAC2STR(bssid));
        return;
    }
    
    rsn_ie_len = rsn_ie[1] + 2;
    
    if (wpa_parse_wpa_ie_rsn(rsn_ie, rsn_ie_len, &rsn_data) != 0) {
        WIFIMON_DEBUG(S_AUTH_HANDLE, "failed to parse RSN IE for mac="MACSTR " bssid=" MACSTR, MAC2STR(mac), MAC2STR(bssid));
        return;
    }
    
    // Определение имени группового шифра - используем полный список констант
    switch (rsn_data.group_cipher) {
        case WPA_CIPHER_NONE:
            strncpy(group_name, "NONE", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_WEP40:
            strncpy(group_name, "WEP40", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_WEP104:
            strncpy(group_name, "WEP104", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_TKIP:
            strncpy(group_name, "TKIP", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_CCMP:
            strncpy(group_name, "CCMP", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_AES_128_CMAC:
            strncpy(group_name, "AES_128_CMAC", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_GCMP:
            strncpy(group_name, "GCMP", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_SMS4:
            strncpy(group_name, "SMS4", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_GCMP_256:
            strncpy(group_name, "GCMP-256", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_CCMP_256:
            strncpy(group_name, "CCMP-256", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_128:
            strncpy(group_name, "BIP_GMAC_128", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_256:
            strncpy(group_name, "BIP_GMAC_256", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_BIP_CMAC_256:
            strncpy(group_name, "BIP_CMAC_256", sizeof(group_name) - 1);
            break;
        case WPA_CIPHER_GTK_NOT_USED:
            strncpy(group_name, "GTK_NOT_USED", sizeof(group_name) - 1);
            break;
        default:
            snprintf(group_name, sizeof(group_name) - 1, "0x%x", rsn_data.group_cipher);
            break;
    }
    group_name[sizeof(group_name) - 1] = '\0';
    
    // Определение имени парного шифра - используем тот же набор констант
    switch (rsn_data.pairwise_cipher) {
        case WPA_CIPHER_NONE:
            strncpy(pairwise_name, "NONE", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_WEP40:
            strncpy(pairwise_name, "WEP40", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_WEP104:
            strncpy(pairwise_name, "WEP104", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_TKIP:
            strncpy(pairwise_name, "TKIP", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_CCMP:
            strncpy(pairwise_name, "CCMP", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_AES_128_CMAC:
            strncpy(pairwise_name, "AES_128_CMAC", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_GCMP:
            strncpy(pairwise_name, "GCMP", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_SMS4:
            strncpy(pairwise_name, "SMS4", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_GCMP_256:
            strncpy(pairwise_name, "GCMP-256", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_CCMP_256:
            strncpy(pairwise_name, "CCMP-256", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_128:
            strncpy(pairwise_name, "BIP_GMAC_128", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_256:
            strncpy(pairwise_name, "BIP_GMAC_256", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_BIP_CMAC_256:
            strncpy(pairwise_name, "BIP_CMAC_256", sizeof(pairwise_name) - 1);
            break;
        case WPA_CIPHER_GTK_NOT_USED:
            strncpy(pairwise_name, "GTK_NOT_USED", sizeof(pairwise_name) - 1);
            break;
        default:
            snprintf(pairwise_name, sizeof(pairwise_name) - 1, "0x%x", rsn_data.pairwise_cipher);
            break;
    }
    pairwise_name[sizeof(pairwise_name) - 1] = '\0';
    
    // Определение имен ключевого менеджмента (включаем все установленные биты)
    key_mgmt_name[0] = '\0';
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192) {
        strcat(key_mgmt_name, "IEEE8021X_SUITE_B_192");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "IEEE8021X_SUITE_B");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X_SHA384) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_IEEE8021X_SHA384");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA384) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "IEEE8021X_SHA384");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_IEEE8021X");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "IEEE8021X_SHA256");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_IEEE8021X) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "IEEE8021X");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_SAE) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_SAE");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_SAE) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "SAE");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_PSK) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_PSK");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_PSK_SHA256) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "PSK_SHA256");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_PSK) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "PSK");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_OWE) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "OWE");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_DPP) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "DPP");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FILS_SHA384) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FILS_SHA384");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FILS_SHA256) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FILS_SHA256");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_WAPI_PSK) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "WAPI_PSK");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_WAPI_CERT) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "WAPI_CERT");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_CCKM) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "CCKM");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_OSEN) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "OSEN");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_FILS_SHA256");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_FILS_SHA384");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_PASN) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "PASN");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_SAE_EXT_KEY) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "SAE_EXT_KEY");
    }
    
    if (rsn_data.key_mgmt & WPA_KEY_MGMT_FT_SAE_EXT_KEY) {
        if (key_mgmt_name[0] != '\0') strcat(key_mgmt_name, "_");
        strcat(key_mgmt_name, "FT_SAE_EXT_KEY");
    }
    
    if (key_mgmt_name[0] == '\0') {
        snprintf(key_mgmt_name, sizeof(key_mgmt_name) - 1, "0x%x", rsn_data.key_mgmt);
    }

    // Определение имени группового шифра для защищенных управляющих кадров
    switch (rsn_data.mgmt_group_cipher) {
        case WPA_CIPHER_NONE:
            strncpy(mgmt_group_name, "NONE", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_WEP40:
            strncpy(mgmt_group_name, "WEP40", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_WEP104:
            strncpy(mgmt_group_name, "WEP104", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_TKIP:
            strncpy(mgmt_group_name, "TKIP", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_CCMP:
            strncpy(mgmt_group_name, "CCMP", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_AES_128_CMAC:
            strncpy(mgmt_group_name, "AES_128_CMAC", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_GCMP:
            strncpy(mgmt_group_name, "GCMP", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_SMS4:
            strncpy(mgmt_group_name, "SMS4", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_GCMP_256:
            strncpy(mgmt_group_name, "GCMP-256", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_CCMP_256:
            strncpy(mgmt_group_name, "CCMP-256", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_128:
            strncpy(mgmt_group_name, "BIP_GMAC_128", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_BIP_GMAC_256:
            strncpy(mgmt_group_name, "BIP_GMAC_256", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_BIP_CMAC_256:
            strncpy(mgmt_group_name, "BIP_CMAC_256", sizeof(mgmt_group_name) - 1);
            break;
        case WPA_CIPHER_GTK_NOT_USED:
            strncpy(mgmt_group_name, "GTK_NOT_USED", sizeof(mgmt_group_name) - 1);
            break;
        default:
            snprintf(mgmt_group_name, sizeof(mgmt_group_name) - 1, "0x%x", rsn_data.mgmt_group_cipher);
            break;
    }
    mgmt_group_name[sizeof(mgmt_group_name) - 1] = '\0';

	WIFIMON_DEBUG(S_AUTH_HANDLE,
					"mac=" MACSTR " bssid=" MACSTR
					" group_cipher=%d group_name=%s"
					" pairwise_cipher=%d pairwise_name=%s"
					" key_mgmt=%d key_mgmt_name=%s"
					" rsn_capab=%d "
					"mgmt_group_cipher=%d mgmt_group_name=%s",
					MAC2STR(mac), MAC2STR(bssid), rsn_data.group_cipher,
					group_name, rsn_data.pairwise_cipher, pairwise_name,
					rsn_data.key_mgmt, key_mgmt_name, rsn_data.capabilities,
					rsn_data.mgmt_group_cipher, mgmt_group_name);
}
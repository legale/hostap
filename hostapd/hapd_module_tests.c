/*
 * hostapd module tests
 * Copyright (c) 2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/module_tests.h"
#include "ap/sta_info.h"
#include "ap/taxonomy.h"
#include "utils/wpabuf.h"

static int taxonomy_test_case(const u8 *probe, size_t probe_len,
			      const u8 *assoc, size_t assoc_len,
			      size_t buflen, const char *name,
			      const char *expected, int expected_ret)
{
	struct sta_info sta;
	char buf[4096];
	int ret;

	os_memset(&sta, 0, sizeof(sta));
	if (probe)
		sta.probe_ie_taxonomy = wpabuf_alloc_copy(probe, probe_len);
	if (assoc)
		sta.assoc_ie_taxonomy = wpabuf_alloc_copy(assoc, assoc_len);
	if ((probe && !sta.probe_ie_taxonomy) ||
	    (assoc && !sta.assoc_ie_taxonomy)) {
		wpa_printf(MSG_ERROR, "taxonomy test %s: allocation failed", name);
		wpabuf_free(sta.probe_ie_taxonomy);
		wpabuf_free(sta.assoc_ie_taxonomy);
		return -1;
	}

	ret = retrieve_sta_taxonomy(NULL, &sta, buf, buflen);
	wpabuf_free(sta.probe_ie_taxonomy);
	wpabuf_free(sta.assoc_ie_taxonomy);
	if (expected_ret == -2 && ret <= 1024) {
		wpa_printf(MSG_ERROR, "taxonomy test %s: ret=%d expected >1024", name, ret);
		return -1;
	}
	if (expected_ret != -2 && ret != expected_ret) {
		wpa_printf(MSG_ERROR, "taxonomy test %s: ret=%d expected=%d", name, ret, expected_ret);
		return -1;
	}
	if (expected && os_strcmp(buf, expected) != 0) {
		wpa_printf(MSG_ERROR, "taxonomy test %s: signature mismatch: %s", name, buf);
		return -1;
	}
	return 0;
}

static int taxonomy_module_tests(void)
{
	static const u8 valid_ie[] = { 0, 0, 1, 1, 2 };
	static const u8 malformed_ie[] = { 1, 5, 0 };
	static u8 long_ie[255 * 6];
	int i;

	if (taxonomy_test_case(valid_ie, sizeof(valid_ie), valid_ie,
			       sizeof(valid_ie), 4096,
			       "complete",
			       "wifi4|probe:0,1|assoc:0,1", 25) < 0)
		return -1;
	if (taxonomy_test_case(NULL, 0, valid_ie, sizeof(valid_ie), 4096,
			       "missing_probe", NULL, 0) < 0)
		return -1;
	if (taxonomy_test_case(malformed_ie, sizeof(malformed_ie), valid_ie,
			       sizeof(valid_ie), 4096, "malformed", NULL, -1) < 0)
		return -1;

	for (i = 0; i < 6; i++) {
		long_ie[i * 255] = WLAN_EID_EXT_CAPAB;
		long_ie[i * 255 + 1] = 253;
		os_memset(&long_ie[i * 255 + 2], i, 253);
	}
	if (taxonomy_test_case(long_ie, sizeof(long_ie), long_ie,
			       sizeof(long_ie), 4096, "long_complete", NULL, -2) < 0)
		return -1;
	if (taxonomy_test_case(long_ie, sizeof(long_ie), long_ie,
			       sizeof(long_ie), 1024, "long_truncated", NULL, -1) < 0)
		return -1;

	return 0;
}

static int taxonomy_wifitax_tests(void)
{
	static const u8 addr[ETH_ALEN] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	static const u8 other_addr[ETH_ALEN] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	static const u8 valid_ie[] = { 0, 0, 1, 1, 2 };
	static const u8 malformed_ie[] = { 1, 5, 0 };
	static u8 long_ie[255 * 6];
	struct hostapd_data hapd, other_hapd;
	struct sta_info sta;
	char signature[TAXONOMY_MAX_SIGNATURE_LEN + 1];
	int i, ret;

	os_memset(&hapd, 0, sizeof(hapd));
	os_memset(&other_hapd, 0, sizeof(other_hapd));
	os_memset(&sta, 0, sizeof(sta));
	os_memcpy(sta.addr, addr, ETH_ALEN);
	hapd.sta_hash[STA_HASH(addr)] = &sta;

	sta.probe_ie_taxonomy = wpabuf_alloc_copy(valid_ie, sizeof(valid_ie));
	sta.assoc_ie_taxonomy = wpabuf_alloc_copy(valid_ie, sizeof(valid_ie));
	if (!sta.probe_ie_taxonomy || !sta.assoc_ie_taxonomy)
		return -1;

	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_COMPLETE ||
	    os_strcmp(signature, "wifi4|probe:0,1|assoc:0,1") != 0)
		return -1;

	wpabuf_free(sta.probe_ie_taxonomy);
	sta.probe_ie_taxonomy = NULL;
	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_MISSING_PROBE || signature[0] != '\0')
		return -1;

	sta.probe_ie_taxonomy = wpabuf_alloc_copy(valid_ie, sizeof(valid_ie));
	wpabuf_free(sta.assoc_ie_taxonomy);
	sta.assoc_ie_taxonomy = NULL;
	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_MISSING_ASSOC || signature[0] != '\0')
		return -1;

	sta.assoc_ie_taxonomy = wpabuf_alloc_copy(malformed_ie, sizeof(malformed_ie));
	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_INVALID_IE || signature[0] != '\0')
		return -1;

	for (i = 0; i < 6; i++) {
		long_ie[i * 255] = WLAN_EID_EXT_CAPAB;
		long_ie[i * 255 + 1] = 253;
		os_memset(&long_ie[i * 255 + 2], i, 253);
	}
	wpabuf_free(sta.probe_ie_taxonomy);
	wpabuf_free(sta.assoc_ie_taxonomy);
	sta.probe_ie_taxonomy = wpabuf_alloc_copy(long_ie, sizeof(long_ie));
	sta.assoc_ie_taxonomy = wpabuf_alloc_copy(long_ie, sizeof(long_ie));
	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_COMPLETE || os_strlen(signature) <= 1024)
		return -1;
	os_memset(signature, 0, sizeof(signature));
	ret = taxonomy_get_sta_wifitax(&hapd, addr, signature, 1024);
	if (ret != TAXONOMY_WIFITAX_INVALID_IE || signature[0] != '\0')
		return -1;

	ret = taxonomy_get_sta_wifitax(&other_hapd, addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_NOT_FOUND)
		return -1;
	ret = taxonomy_get_sta_wifitax(&hapd, other_addr, signature, sizeof(signature));
	if (ret != TAXONOMY_WIFITAX_NOT_FOUND)
		return -1;

	wpabuf_free(sta.probe_ie_taxonomy);
	wpabuf_free(sta.assoc_ie_taxonomy);
	return 0;
}

int hapd_module_tests(void)
{
	wpa_printf(MSG_INFO, "hostapd module tests");
	if (taxonomy_module_tests() < 0) {
		wpa_printf(MSG_ERROR, "taxonomy module tests failed");
		return -1;
	}
	if (taxonomy_wifitax_tests() < 0) {
		wpa_printf(MSG_ERROR, "taxonomy get_wifitax tests failed");
		return -1;
	}
	return 0;
}

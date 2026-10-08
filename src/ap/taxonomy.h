/*
 * hostapd / Station client taxonomy
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef TAXONOMY_H
#define TAXONOMY_H

#define TAXONOMY_MAX_SIGNATURE_LEN 4096

enum taxonomy_wifitax_result {
	TAXONOMY_WIFITAX_COMPLETE,
	TAXONOMY_WIFITAX_MISSING_PROBE,
	TAXONOMY_WIFITAX_MISSING_ASSOC,
	TAXONOMY_WIFITAX_INVALID_IE,
	TAXONOMY_WIFITAX_NOT_FOUND
};

void taxonomy_sta_info_probe_req(const struct hostapd_data *hapd,
				 struct sta_info *sta,
				 const u8 *ie, size_t ie_len);
void taxonomy_hostapd_sta_info_probe_req(const struct hostapd_data *hapd,
					 struct hostapd_sta_info *sta,
					 const u8 *ie, size_t ie_len);
void taxonomy_sta_info_assoc_req(const struct hostapd_data *hapd,
				 struct sta_info *sta,
				 const u8 *ie, size_t ie_len);
int retrieve_sta_taxonomy(const struct hostapd_data *hapd,
			  struct sta_info *sta, char *buf, size_t buflen);
int taxonomy_get_sta_wifitax(struct hostapd_data *hapd, const u8 *addr,
			      char *signature, size_t signature_len);

#endif /* TAXONOMY_H */

/* WPA Supplicant - Windows WLAN API driver interface */

#include "includes.h"
#include <wlanapi.h>

#include "common.h"
#include "driver.h"
#include "eloop.h"

struct wlanapi_data {
	void *ctx;
	HANDLE handle;
	GUID guid;
	char ifname[IFNAMSIZ];
};

static int wlanapi_guid_string(const GUID *guid, char *buf, size_t len)
{
	WCHAR wbuf[64];

	if (StringFromGUID2(guid, wbuf, ARRAY_SIZE(wbuf)) == 0 ||
		WideCharToMultiByte(CP_ACP, 0, wbuf, -1, buf, len, NULL, NULL) == 0)
		return -1;
	return 0;
}

static int wlanapi_find_interface(struct wlanapi_data *drv, const char *ifname)
{
	WLAN_INTERFACE_INFO_LIST *list = NULL;
	DWORD ret;

	ret = WlanEnumInterfaces(drv->handle, NULL, &list);
	if (ret != ERROR_SUCCESS)
		return -1;

	for (DWORD i = 0; i < list->dwNumberOfItems; i++) {
		WLAN_INTERFACE_INFO *iface = &list->InterfaceInfo[i];
		char guid[64];
		char desc[WLAN_MAX_NAME_LENGTH];

		if (wlanapi_guid_string(&iface->InterfaceGuid, guid, sizeof(guid)) < 0)
			continue;
		if (WideCharToMultiByte(CP_ACP, 0, iface->strInterfaceDescription,
						-1, desc, sizeof(desc), NULL, NULL) == 0)
			continue;
		if (os_strcasecmp(ifname, guid) == 0 ||
			os_strcasecmp(ifname, desc) == 0) {
			drv->guid = iface->InterfaceGuid;
			os_strlcpy(drv->ifname, guid, sizeof(drv->ifname));
			WlanFreeMemory(list);
			return 0;
		}
	}

	WlanFreeMemory(list);
	return -1;
}

static void wlanapi_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wlanapi_data *drv = eloop_ctx;

	(void) timeout_ctx;
	wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
}

static int wlanapi_scan(void *priv, struct wpa_driver_scan_params *params)
{
	struct wlanapi_data *drv = priv;
	DOT11_SSID ssid;
	PDOT11_SSID ssid_ptr = NULL;
	DWORD ret;

	if (params && params->num_ssids == 1 && params->ssids[0].ssid &&
		params->ssids[0].ssid_len <= DOT11_SSID_MAX_LENGTH) {
		os_memset(&ssid, 0, sizeof(ssid));
		ssid.uSSIDLength = params->ssids[0].ssid_len;
		os_memcpy(ssid.ucSSID, params->ssids[0].ssid, ssid.uSSIDLength);
		ssid_ptr = &ssid;
	}

	ret = WlanScan(drv->handle, &drv->guid, ssid_ptr, NULL, NULL);
	if (ret != ERROR_SUCCESS) {
		wpa_printf(MSG_DEBUG, "WLANAPI: WlanScan failed: %lu",
			   (unsigned long) ret);
		return -1;
	}

	eloop_cancel_timeout(wlanapi_scan_timeout, drv, NULL);
	return eloop_register_timeout(4, 0, wlanapi_scan_timeout, drv, NULL);
}

static struct wpa_scan_results *
wlanapi_get_scan_results(void *priv)
{
	struct wlanapi_data *drv = priv;
	PWLAN_BSS_LIST list = NULL;
	struct wpa_scan_results *results;
	DWORD ret;

	ret = WlanGetNetworkBssList(drv->handle, &drv->guid, NULL,
					   dot11_BSS_type_any, FALSE, NULL, &list);
	if (ret != ERROR_SUCCESS)
		return NULL;

	results = os_zalloc(sizeof(*results));
	if (results == NULL)
		goto out;
	results->res = os_calloc(list->dwNumberOfItems,
					 sizeof(*results->res));
	if (results->res == NULL) {
		os_free(results);
		results = NULL;
		goto out;
	}

	for (DWORD i = 0; i < list->dwNumberOfItems; i++) {
		PWLAN_BSS_ENTRY entry = &list->wlanBssEntries[i];
		struct wpa_scan_res *res;
		u8 *ies;

		if (entry->ulIeSize > list->dwTotalSize ||
			entry->ulIeOffset > list->dwTotalSize - entry->ulIeSize)
			continue;
		res = os_zalloc(sizeof(*res) + entry->ulIeSize);
		if (res == NULL)
			continue;
		os_memcpy(res->bssid, entry->dot11Bssid, ETH_ALEN);
		res->freq = entry->ulChCenterFrequency / 1000;
		res->level = entry->lRssi;
		res->qual = entry->uLinkQuality;
		res->beacon_int = entry->usBeaconPeriod;
		res->caps = entry->usCapabilityInformation;
		res->tsf = entry->ullTimestamp;
		res->ie_len = entry->ulIeSize;
		ies = (u8 *) entry + entry->ulIeOffset;
		os_memcpy(res + 1, ies, entry->ulIeSize);
		results->res[results->num++] = res;
	}

out:
	WlanFreeMemory(list);
	return results;
}

static void * wlanapi_init(void *ctx, const char *ifname)
{
	struct wlanapi_data *drv;
	DWORD version, ret;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->ctx = ctx;
	ret = WlanOpenHandle(2, NULL, &version, &drv->handle);
	if (ret != ERROR_SUCCESS || wlanapi_find_interface(drv, ifname) < 0) {
		wpa_printf(MSG_ERROR, "WLANAPI: cannot open interface %s", ifname);
		if (drv->handle)
			WlanCloseHandle(drv->handle, NULL);
		os_free(drv);
		return NULL;
	}
	return drv;
}

static void wlanapi_deinit(void *priv)
{
	struct wlanapi_data *drv = priv;

	eloop_cancel_timeout(wlanapi_scan_timeout, drv, NULL);
	WlanCloseHandle(drv->handle, NULL);
	os_free(drv);
}

static int wlanapi_get_ifname(void *priv, char *buf, size_t len)
{
	struct wlanapi_data *drv = priv;

	os_strlcpy(buf, drv->ifname, len);
	return 0;
}

static struct wpa_interface_info *wlanapi_get_interfaces(void *global_priv)
{
	struct wpa_interface_info *head = NULL, *item;
	struct wlanapi_data drv;
	WLAN_INTERFACE_INFO_LIST *list = NULL;
	DWORD version, ret;

	(void) global_priv;
	os_memset(&drv, 0, sizeof(drv));
	ret = WlanOpenHandle(2, NULL, &version, &drv.handle);
	if (ret != ERROR_SUCCESS)
		return NULL;
	ret = WlanEnumInterfaces(drv.handle, NULL, &list);
	if (ret != ERROR_SUCCESS)
		goto out;

	for (DWORD i = 0; i < list->dwNumberOfItems; i++) {
		WLAN_INTERFACE_INFO *iface = &list->InterfaceInfo[i];
		char guid[64], desc[WLAN_MAX_NAME_LENGTH];

		if (wlanapi_guid_string(&iface->InterfaceGuid, guid, sizeof(guid)) < 0 ||
			WideCharToMultiByte(CP_ACP, 0, iface->strInterfaceDescription,
						-1, desc, sizeof(desc), NULL, NULL) == 0)
			continue;
		item = os_zalloc(sizeof(*item));
		if (item == NULL)
			break;
		item->ifname = os_strdup(guid);
		item->desc = os_strdup(desc);
		item->drv_name = "wlanapi";
		if (item->ifname == NULL || item->desc == NULL) {
			os_free(item->ifname);
			os_free(item->desc);
			os_free(item);
			break;
		}
		item->next = head;
		head = item;
	}

out:
	if (list)
		WlanFreeMemory(list);
	WlanCloseHandle(drv.handle, NULL);
	return head;
}

const struct wpa_driver_ops wpa_driver_wlanapi_ops = {
	.name = "wlanapi",
	.desc = "Windows WLAN API driver",
	.init = wlanapi_init,
	.deinit = wlanapi_deinit,
	.get_ifname = wlanapi_get_ifname,
	.scan2 = wlanapi_scan,
	.get_scan_results2 = wlanapi_get_scan_results,
	.get_interfaces = wlanapi_get_interfaces,
};

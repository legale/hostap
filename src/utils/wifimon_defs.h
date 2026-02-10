/*
 * wifimon - Wi-Fi monitoring definitions
 *
 * Stages, status codes, wifimon_code_t enum, and WIFIMON_* logging macros.
 *
 * Every WIFIMON message contains mandatory tokens:
 *   wifimon_status=N stage=N code=N sc=N rc=N [free text key=value ...]
 */

#ifndef WIFIMON_H
#define WIFIMON_H

#ifndef __FILENAME__
#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

/* ------------------------------------------------------------------ */
/*  wifi_stage_t                                                       */
/* ------------------------------------------------------------------ */

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
	S_L3_UP = 22,             // client station ip assigned (no corresponding tx/rx event)
} wifi_stage_t;

/* ------------------------------------------------------------------ */
/*  wifimon_status_t                                                   */
/* ------------------------------------------------------------------ */

typedef enum wifimon_status {
	WIFIMON_OK = 0,
	WIFIMON_INF = 1,
	WIFIMON_ERR = 2,
	WIFIMON_WARN = 3,
} wifimon_status_t;

/* ------------------------------------------------------------------ */
/*  wifimon_code_t                                                     */
/*                                                                     */
/*  code ranges:                                                       */
/*    0x0000 .. 0x0FFF  - local AP codes (WMC_OK, WMC_LOC_*)          */
/*    0x1000 .. 0x1FFF  - IEEE 802.11 Status Code  (WMC_T_SC + sc)    */
/*    0x2000 .. 0x2FFF  - IEEE 802.11 Reason Code  (WMC_T_RC + rc)    */
/* ------------------------------------------------------------------ */

#define WMC_T_SC  0x1000u
#define WMC_T_RC  0x2000u

typedef enum wifimon_code {
	WMC_OK = 0,

	/* local AP codes — internal decisions without an 802.11 frame */
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
	WMC_LOC_PSK_MISMATCH = 16,
} wifimon_code_t;

/*
 * IEEE 802.11 Status Code derived wifimon codes: WMC_T_SC + WLAN_STATUS_*
 * Defined as macros (not enum) to avoid circular dependency on
 * ieee802_11_defs.h — macros expand at point of use in .c files
 * where WLAN_STATUS_* are already available.
 */
#define WMC_SC_WLAN_STATUS_SUCCESS                         ((int)(WMC_T_SC + WLAN_STATUS_SUCCESS))
#define WMC_SC_WLAN_STATUS_UNSPECIFIED_FAILURE              ((int)(WMC_T_SC + WLAN_STATUS_UNSPECIFIED_FAILURE))
#define WMC_SC_WLAN_STATUS_TDLS_WAKEUP_ALTERNATE            ((int)(WMC_T_SC + WLAN_STATUS_TDLS_WAKEUP_ALTERNATE))
#define WMC_SC_WLAN_STATUS_TDLS_WAKEUP_REJECT               ((int)(WMC_T_SC + WLAN_STATUS_TDLS_WAKEUP_REJECT))
#define WMC_SC_WLAN_STATUS_SECURITY_DISABLED                ((int)(WMC_T_SC + WLAN_STATUS_SECURITY_DISABLED))
#define WMC_SC_WLAN_STATUS_UNACCEPTABLE_LIFETIME            ((int)(WMC_T_SC + WLAN_STATUS_UNACCEPTABLE_LIFETIME))
#define WMC_SC_WLAN_STATUS_NOT_IN_SAME_BSS                  ((int)(WMC_T_SC + WLAN_STATUS_NOT_IN_SAME_BSS))
#define WMC_SC_WLAN_STATUS_CAPS_UNSUPPORTED                 ((int)(WMC_T_SC + WLAN_STATUS_CAPS_UNSUPPORTED))
#define WMC_SC_WLAN_STATUS_REASSOC_NO_ASSOC                 ((int)(WMC_T_SC + WLAN_STATUS_REASSOC_NO_ASSOC))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_UNSPEC              ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_UNSPEC))
#define WMC_SC_WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG           ((int)(WMC_T_SC + WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG))
#define WMC_SC_WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION         ((int)(WMC_T_SC + WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION))
#define WMC_SC_WLAN_STATUS_CHALLENGE_FAIL                   ((int)(WMC_T_SC + WLAN_STATUS_CHALLENGE_FAIL))
#define WMC_SC_WLAN_STATUS_AUTH_TIMEOUT                     ((int)(WMC_T_SC + WLAN_STATUS_AUTH_TIMEOUT))
#define WMC_SC_WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA      ((int)(WMC_T_SC + WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_RATES               ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_RATES))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_NOSHORT             ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NOSHORT))
#define WMC_SC_WLAN_STATUS_SPEC_MGMT_REQUIRED               ((int)(WMC_T_SC + WLAN_STATUS_SPEC_MGMT_REQUIRED))
#define WMC_SC_WLAN_STATUS_PWR_CAPABILITY_NOT_VALID         ((int)(WMC_T_SC + WLAN_STATUS_PWR_CAPABILITY_NOT_VALID))
#define WMC_SC_WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID      ((int)(WMC_T_SC + WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_SHORT_SLOT_TIME  ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_SHORT_SLOT_TIME))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_HT               ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_HT))
#define WMC_SC_WLAN_STATUS_R0KH_UNREACHABLE                 ((int)(WMC_T_SC + WLAN_STATUS_R0KH_UNREACHABLE))
#define WMC_SC_WLAN_STATUS_ASSOC_DENIED_NO_PCO              ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_DENIED_NO_PCO))
#define WMC_SC_WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY       ((int)(WMC_T_SC + WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY))
#define WMC_SC_WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION ((int)(WMC_T_SC + WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION))
#define WMC_SC_WLAN_STATUS_UNSPECIFIED_QOS_FAILURE          ((int)(WMC_T_SC + WLAN_STATUS_UNSPECIFIED_QOS_FAILURE))
#define WMC_SC_WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH    ((int)(WMC_T_SC + WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH))
#define WMC_SC_WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS   ((int)(WMC_T_SC + WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS))
#define WMC_SC_WLAN_STATUS_DENIED_QOS_NOT_SUPPORTED         ((int)(WMC_T_SC + WLAN_STATUS_DENIED_QOS_NOT_SUPPORTED))
#define WMC_SC_WLAN_STATUS_REQUEST_DECLINED                 ((int)(WMC_T_SC + WLAN_STATUS_REQUEST_DECLINED))
#define WMC_SC_WLAN_STATUS_INVALID_PARAMETERS               ((int)(WMC_T_SC + WLAN_STATUS_INVALID_PARAMETERS))
#define WMC_SC_WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES  ((int)(WMC_T_SC + WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES))
#define WMC_SC_WLAN_STATUS_INVALID_IE                       ((int)(WMC_T_SC + WLAN_STATUS_INVALID_IE))
#define WMC_SC_WLAN_STATUS_GROUP_CIPHER_NOT_VALID           ((int)(WMC_T_SC + WLAN_STATUS_GROUP_CIPHER_NOT_VALID))
#define WMC_SC_WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID        ((int)(WMC_T_SC + WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID))
#define WMC_SC_WLAN_STATUS_AKMP_NOT_VALID                   ((int)(WMC_T_SC + WLAN_STATUS_AKMP_NOT_VALID))
#define WMC_SC_WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION       ((int)(WMC_T_SC + WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION))
#define WMC_SC_WLAN_STATUS_INVALID_RSN_IE_CAPAB             ((int)(WMC_T_SC + WLAN_STATUS_INVALID_RSN_IE_CAPAB))
#define WMC_SC_WLAN_STATUS_CIPHER_REJECTED_PER_POLICY       ((int)(WMC_T_SC + WLAN_STATUS_CIPHER_REJECTED_PER_POLICY))
#define WMC_SC_WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT    ((int)(WMC_T_SC + WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT))
#define WMC_SC_WLAN_STATUS_INVALID_PMKID                    ((int)(WMC_T_SC + WLAN_STATUS_INVALID_PMKID))
#define WMC_SC_WLAN_STATUS_INVALID_MDIE                     ((int)(WMC_T_SC + WLAN_STATUS_INVALID_MDIE))
#define WMC_SC_WLAN_STATUS_INVALID_FTIE                     ((int)(WMC_T_SC + WLAN_STATUS_INVALID_FTIE))
#define WMC_SC_WLAN_STATUS_TRY_ANOTHER_BSS                  ((int)(WMC_T_SC + WLAN_STATUS_TRY_ANOTHER_BSS))
#define WMC_SC_WLAN_STATUS_TRANSMISSION_FAILURE             ((int)(WMC_T_SC + WLAN_STATUS_TRANSMISSION_FAILURE))
#define WMC_SC_WLAN_STATUS_REFUSED_EXTERNAL_REASON          ((int)(WMC_T_SC + WLAN_STATUS_REFUSED_EXTERNAL_REASON))
#define WMC_SC_WLAN_STATUS_REFUSED_AP_OUT_OF_MEMORY         ((int)(WMC_T_SC + WLAN_STATUS_REFUSED_AP_OUT_OF_MEMORY))
#define WMC_SC_WLAN_STATUS_FILS_AUTHENTICATION_FAILURE      ((int)(WMC_T_SC + WLAN_STATUS_FILS_AUTHENTICATION_FAILURE))
#define WMC_SC_WLAN_STATUS_UNKNOWN_AUTHENTICATION_SERVER    ((int)(WMC_T_SC + WLAN_STATUS_UNKNOWN_AUTHENTICATION_SERVER))
#define WMC_SC_WLAN_STATUS_DENIED_HE_NOT_SUPPORTED          ((int)(WMC_T_SC + WLAN_STATUS_DENIED_HE_NOT_SUPPORTED))
#define WMC_SC_WLAN_STATUS_SAE_HASH_TO_ELEMENT              ((int)(WMC_T_SC + WLAN_STATUS_SAE_HASH_TO_ELEMENT))
#define WMC_SC_WLAN_STATUS_SAE_PK                           ((int)(WMC_T_SC + WLAN_STATUS_SAE_PK))
#define WMC_SC_WLAN_STATUS_OCI_MISMATCH                     ((int)(WMC_T_SC + WLAN_STATUS_OCI_MISMATCH))

/*
 * IEEE 802.11 Reason Code derived wifimon codes: WMC_T_RC + WLAN_REASON_*
 */
#define WMC_RC_WLAN_REASON_UNSPECIFIED                      ((int)(WMC_T_RC + WLAN_REASON_UNSPECIFIED))
#define WMC_RC_WLAN_REASON_PREV_AUTH_NOT_VALID              ((int)(WMC_T_RC + WLAN_REASON_PREV_AUTH_NOT_VALID))
#define WMC_RC_WLAN_REASON_DEAUTH_LEAVING                   ((int)(WMC_T_RC + WLAN_REASON_DEAUTH_LEAVING))
#define WMC_RC_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY       ((int)(WMC_T_RC + WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY))
#define WMC_RC_WLAN_REASON_DISASSOC_AP_BUSY                 ((int)(WMC_T_RC + WLAN_REASON_DISASSOC_AP_BUSY))
#define WMC_RC_WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA    ((int)(WMC_T_RC + WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA))
#define WMC_RC_WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA   ((int)(WMC_T_RC + WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA))
#define WMC_RC_WLAN_REASON_DISASSOC_STA_HAS_LEFT            ((int)(WMC_T_RC + WLAN_REASON_DISASSOC_STA_HAS_LEFT))
#define WMC_RC_WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH       ((int)(WMC_T_RC + WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH))
#define WMC_RC_WLAN_REASON_PWR_CAPABILITY_NOT_VALID         ((int)(WMC_T_RC + WLAN_REASON_PWR_CAPABILITY_NOT_VALID))
#define WMC_RC_WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID      ((int)(WMC_T_RC + WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID))
#define WMC_RC_WLAN_REASON_BSS_TRANSITION_DISASSOC          ((int)(WMC_T_RC + WLAN_REASON_BSS_TRANSITION_DISASSOC))
#define WMC_RC_WLAN_REASON_INVALID_IE                       ((int)(WMC_T_RC + WLAN_REASON_INVALID_IE))
#define WMC_RC_WLAN_REASON_MICHAEL_MIC_FAILURE              ((int)(WMC_T_RC + WLAN_REASON_MICHAEL_MIC_FAILURE))
#define WMC_RC_WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT           ((int)(WMC_T_RC + WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT))
#define WMC_RC_WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT         ((int)(WMC_T_RC + WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT))
#define WMC_RC_WLAN_REASON_IE_IN_4WAY_DIFFERS               ((int)(WMC_T_RC + WLAN_REASON_IE_IN_4WAY_DIFFERS))
#define WMC_RC_WLAN_REASON_GROUP_CIPHER_NOT_VALID           ((int)(WMC_T_RC + WLAN_REASON_GROUP_CIPHER_NOT_VALID))
#define WMC_RC_WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID        ((int)(WMC_T_RC + WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID))
#define WMC_RC_WLAN_REASON_AKMP_NOT_VALID                   ((int)(WMC_T_RC + WLAN_REASON_AKMP_NOT_VALID))
#define WMC_RC_WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION       ((int)(WMC_T_RC + WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION))
#define WMC_RC_WLAN_REASON_INVALID_RSN_IE_CAPAB             ((int)(WMC_T_RC + WLAN_REASON_INVALID_RSN_IE_CAPAB))
#define WMC_RC_WLAN_REASON_IEEE_802_1X_AUTH_FAILED          ((int)(WMC_T_RC + WLAN_REASON_IEEE_802_1X_AUTH_FAILED))
#define WMC_RC_WLAN_REASON_CIPHER_SUITE_REJECTED            ((int)(WMC_T_RC + WLAN_REASON_CIPHER_SUITE_REJECTED))
#define WMC_RC_WLAN_REASON_BAD_CIPHER_OR_AKM                ((int)(WMC_T_RC + WLAN_REASON_BAD_CIPHER_OR_AKM))
#define WMC_RC_WLAN_REASON_NOT_AUTHORIZED_THIS_LOCATION     ((int)(WMC_T_RC + WLAN_REASON_NOT_AUTHORIZED_THIS_LOCATION))
#define WMC_RC_WLAN_REASON_DISASSOC_LOW_ACK                 ((int)(WMC_T_RC + WLAN_REASON_DISASSOC_LOW_ACK))
#define WMC_RC_WLAN_REASON_TIMEOUT                          ((int)(WMC_T_RC + WLAN_REASON_TIMEOUT))

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */

static inline wifimon_code_t wifimon_code_from_status(int sc)
{
	return (wifimon_code_t)(WMC_T_SC + (unsigned int)sc);
}

static inline wifimon_code_t wifimon_code_from_reason(int rc)
{
	return (wifimon_code_t)(WMC_T_RC + (unsigned int)rc);
}

/* ------------------------------------------------------------------ */
/*  forward declarations used by macros                                */
/* ------------------------------------------------------------------ */

void wpa_msg_glo(int level, const char *fmt, ...);

/* ------------------------------------------------------------------ */
/*  WIFIMON_* logging macros                                           */
/*                                                                     */
/*  Parameters:                                                        */
/*    wifimon_status - WIFIMON_OK / WIFIMON_INF / WIFIMON_ERR / WARN   */
/*    stage          - wifi_stage_t value                               */
/*    code           - wifimon_code_t (WMC_OK, WMC_LOC_*, or           */
/*                     WMC_T_SC+sc, WMC_T_RC+rc)                      */
/*    sc             - raw IEEE 802.11 status_code  (0 if N/A)         */
/*    rc             - raw IEEE 802.11 reason_code  (0 if N/A)         */
/*    fmt, ...       - free-form text (key=value style recommended)    */
/* ------------------------------------------------------------------ */

#define WIFIMON_MSG(wifimon_status, stage, code, sc, rc, fmt, ...) \
	wpa_msg_glo(MSG_WIFIMON, "%s:%d: %s: wifimon_status=%d stage=%d code=%d sc=%d rc=%d " fmt, \
		__FILENAME__, __LINE__, __FUNCTION__, \
		(int)(wifimon_status), (int)(stage), (int)(code), (int)(sc), (int)(rc), ##__VA_ARGS__)

#define WIFIMON_OK(stage, code, sc, rc, fmt, ...)   WIFIMON_MSG(WIFIMON_OK,   stage, code, sc, rc, fmt, ##__VA_ARGS__)
#define WIFIMON_INF(stage, code, sc, rc, fmt, ...)  WIFIMON_MSG(WIFIMON_INF,  stage, code, sc, rc, fmt, ##__VA_ARGS__)
#define WIFIMON_ERR(stage, code, sc, rc, fmt, ...)  WIFIMON_MSG(WIFIMON_ERR,  stage, code, sc, rc, fmt, ##__VA_ARGS__)
#define WIFIMON_WARN(stage, code, sc, rc, fmt, ...) WIFIMON_MSG(WIFIMON_WARN, stage, code, sc, rc, fmt, ##__VA_ARGS__)
#define WIFIMON_DEBUG(stage, code, sc, rc, fmt, ...) WIFIMON_MSG(WIFIMON_INF, stage, code, sc, rc, fmt, ##__VA_ARGS__)

#endif /* WIFIMON_H */

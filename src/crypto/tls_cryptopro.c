/*
 * CryptoPro SSPI TLS wrapper for EAP-TLS peer
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "tls.h"

#include <cpcsp/CSP_WinDef.h>
#include <cpcsp/CSP_WinError.h>
#include <cpcsp/CSP_WinCrypt.h>
#define SECURITY_WIN32
#include <cpcsp/CSP_Sspi.h>
#include <cpcsp/CSP_SChannel.h>

#include <string.h>

#define CSP_CERT_HASH_LEN 20
#define GOST_TLS12_SUITE 0xc100

struct tls_context {
  PSecurityFunctionTable sspi;
  struct tls_config conf;
  int errors;
};

struct tls_connection {
  struct tls_context *ctx;
  PCCERT_CONTEXT cert;
  HCERTSTORE ca_store;
  HCERTSTORE root_store;
  CredHandle cred;
  CtxtHandle ctxt;
  int have_cred;
  int have_ctxt;
  int established;
  int failed;
  int read_alerts;
  int write_alerts;
  int own_cert_used;
  u8 client_random[32];
  u8 server_random[32];
  int have_client_random;
  int have_server_random;
  u16 cipher_suite;
  char *server_name;
};

static void csp_error(struct tls_connection *conn, const char *op,
                      SECURITY_STATUS status)
{
  wpa_printf(MSG_INFO, "CryptoPro: event=error op='%s' status=0x%08lx", op,
             (unsigned long) status);
  conn->failed = 1;
  conn->ctx->errors++;
}

static void format_hex(const u8 *bin, size_t len, char *out, size_t out_len)
{
  size_t i;
  if (out_len < len * 2 + 1)
    return;
  for (i = 0; i < len; i++)
    os_snprintf(out + i * 2, 3, "%02x", bin[i]);
  out[len * 2] = '\0';
}

static PCCERT_CONTEXT find_cert(const u8 wanted[CSP_CERT_HASH_LEN])
{
  HCERTSTORE store;
  PCCERT_CONTEXT cert = NULL;
  PCCERT_CONTEXT found = NULL;
  char wanted_hex[CSP_CERT_HASH_LEN * 2 + 1];

  format_hex(wanted, CSP_CERT_HASH_LEN, wanted_hex, sizeof(wanted_hex));

  store = CertOpenSystemStoreA(0, "MY");
  if (!store) {
    wpa_printf(MSG_INFO, "CryptoPro: event=open_store store=MY status=failed error=0x%08lx",
               (unsigned long) GetLastError());
    return NULL;
  }
  wpa_printf(MSG_INFO, "CryptoPro: event=search_store store=MY wanted_thumbprint=%s",
             wanted_hex);

  while ((cert = CertEnumCertificatesInStore(store, cert))) {
    DWORD hash_len = CSP_CERT_HASH_LEN;
    u8 hash[CSP_CERT_HASH_LEN];

    if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
                                           hash, &hash_len) ||
        hash_len != CSP_CERT_HASH_LEN ||
        os_memcmp(hash, wanted, sizeof(hash)))
      continue;

    if (CertVerifyTimeValidity(NULL, cert->pCertInfo) != 0) {
      wpa_printf(MSG_INFO, "CryptoPro: event=check_cert status=expired thumbprint=%s",
                 wanted_hex);
      break;
    }

    found = CertDuplicateCertificateContext(cert);
    break;
  }

  if (cert)
    CertFreeCertificateContext(cert);
  CertCloseStore(store, 0);
  wpa_printf(MSG_INFO, "CryptoPro: event=search_store store=MY status=%s thumbprint=%s",
             found ? "found" : "not_found", wanted_hex);
  return found;
}

static int set_certificate_pin(PCCERT_CONTEXT cert, const char *pin)
{
  DWORD info_len = 0;
  PCRYPT_KEY_PROV_INFO info;
  CRYPT_KEY_PROV_INFO updated;
  CRYPT_KEY_PROV_PARAM param;
  BOOL ok;

  if (!pin) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_pin status=not_configured");
    return 0;
  }
  if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                         NULL, &info_len))
    return -1;
  info = os_malloc(info_len);
  if (!info || !CertGetCertificateContextProperty(cert,
      CERT_KEY_PROV_INFO_PROP_ID, info, &info_len)) {
    os_free(info);
    return -1;
  }
  os_memset(&param, 0, sizeof(param));
  param.dwParam = info->dwKeySpec == AT_SIGNATURE ? PP_SIGNATURE_PIN :
                  PP_KEYEXCHANGE_PIN;
  param.pbData = (BYTE *) pin;
  param.cbData = os_strlen(pin) + 1;
  updated = *info;
  updated.cProvParam = 1;
  updated.rgProvParam = &param;
  ok = CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                         0, &updated);
  wpa_printf(MSG_INFO, "CryptoPro: event=set_pin status=%s key_spec=%lu param=%s",
             ok ? "success" : "failed",
             (unsigned long) info->dwKeySpec,
             info->dwKeySpec == AT_SIGNATURE ? "PP_SIGNATURE_PIN" : "PP_KEYEXCHANGE_PIN");
  os_free(info);
  return ok ? 0 : -1;
}

static void log_certificate_details(PCCERT_CONTEXT cert)
{
  char subject[256];
  DWORD info_len = 0;
  PCRYPT_KEY_PROV_INFO info = NULL;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
  HCRYPTKEY exchange_key = 0;
  BOOL free_key = FALSE;
  DWORD key_spec = 0;

  subject[0] = '\0';
  CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                     subject, sizeof(subject));
  wpa_printf(MSG_INFO, "CryptoPro: event=client_cert subject='%s'", subject);

  if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                        NULL, &info_len)) {
    info = os_malloc(info_len);
    if (info && CertGetCertificateContextProperty(cert,
        CERT_KEY_PROV_INFO_PROP_ID, info, &info_len)) {
      wpa_printf(MSG_INFO,
                 "CryptoPro: event=client_cert_provider provider='%ls' prov_type=%lu key_spec=%lu container='%ls'",
                 info->pwszProvName ? info->pwszProvName : L"(none)",
                 (unsigned long) info->dwProvType,
                 (unsigned long) info->dwKeySpec,
                 info->pwszContainerName ? info->pwszContainerName : L"(none)");
    }
  }

  if (!CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_SILENT_FLAG,
                                         NULL, &key, &key_spec, &free_key)) {
    wpa_printf(MSG_INFO,
               "CryptoPro: event=acquire_private_key status=failed error=0x%08lx",
               (unsigned long) GetLastError());
    os_free(info);
    return;
  }

  wpa_printf(MSG_INFO, "CryptoPro: event=acquire_private_key status=success key_spec=%lu",
             (unsigned long) key_spec);
  if (CryptGetUserKey((HCRYPTPROV) key, AT_KEYEXCHANGE, &exchange_key)) {
    wpa_printf(MSG_INFO, "CryptoPro: event=check_exchange_key status=available");
    CryptDestroyKey(exchange_key);
  } else {
    wpa_printf(MSG_INFO, "CryptoPro: event=check_exchange_key status=unavailable error=0x%08lx",
               (unsigned long) GetLastError());
  }
  if (free_key)
    CryptReleaseContext((HCRYPTPROV) key, 0);
  os_free(info);
}

static int bind_certificate_provider(PCCERT_CONTEXT cert)
{
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
  DWORD key_spec = 0;
  BOOL free_key = FALSE;
  DWORD info_len = 0;
  PCRYPT_KEY_PROV_INFO info = NULL;
  CRYPT_KEY_PROV_INFO updated;
  DWORD name_len = 0;
  char *provider_a = NULL;
  wchar_t *provider = NULL;
  int ret = -1;
  DWORD i;

  if (!CryptAcquireCertificatePrivateKey(cert,
      CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
      NULL, &key, &key_spec, &free_key))
    goto out;
  if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                         NULL, &info_len))
    goto out;
  info = os_malloc(info_len);
  if (!info || !CertGetCertificateContextProperty(cert,
      CERT_KEY_PROV_INFO_PROP_ID, info, &info_len))
    goto out;
  if (!CryptGetProvParam((HCRYPTPROV) key, PP_NAME, NULL, &name_len, 0) ||
      !name_len)
    goto out;
  provider_a = os_malloc(name_len);
  if (!provider_a || !CryptGetProvParam((HCRYPTPROV) key, PP_NAME,
      (BYTE *) provider_a, &name_len, 0))
    goto out;
  provider = os_malloc(name_len * sizeof(*provider));
  if (!provider)
    goto out;
  for (i = 0; i < name_len; i++)
    provider[i] = (wchar_t) (unsigned char) provider_a[i];

  updated = *info;
  updated.pwszProvName = provider;
  updated.dwKeySpec = key_spec;
  if (!CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                          0, &updated))
    goto out;
  wpa_printf(MSG_INFO, "CryptoPro: event=bind_provider status=success provider='%ls' key_spec=%lu",
             provider, (unsigned long) key_spec);
  ret = 0;

out:
  if (ret)
    wpa_printf(MSG_INFO, "CryptoPro: event=bind_provider status=failed error=0x%08lx",
               (unsigned long) GetLastError());
  os_free(provider);
  os_free(provider_a);
  os_free(info);
  if (free_key)
    CryptReleaseContext((HCRYPTPROV) key, 0);
  return ret;
}

static int read_file(const char *path, u8 **data, DWORD *data_len)
{
  FILE *f;
  long len;
  u8 *buf;

  f = fopen(path, "rb");
  if (!f)
    return -1;
  if (fseek(f, 0, SEEK_END) || (len = ftell(f)) <= 0 ||
      len > 16 * 1024 * 1024 || fseek(f, 0, SEEK_SET)) {
    fclose(f);
    return -1;
  }

  buf = os_malloc((size_t) len + 1);
  if (!buf) {
    fclose(f);
    return -1;
  }
  if (fread(buf, 1, (size_t) len, f) != (size_t) len) {
    fclose(f);
    os_free(buf);
    return -1;
  }
  fclose(f);
  buf[len] = '\0';
  *data = buf;
  *data_len = (DWORD) len;
  return 0;
}

struct cpro_key_config {
  char *pin;
  char *domain_match;
};

static void parse_cpro_key_file(const char *path, struct cpro_key_config *cfg)
{
	char *data, *tmp, *line, *save;
	DWORD len;
	int cpro = 0;

	os_memset(cfg, 0, sizeof(*cfg));

	if (!path || read_file(path, (u8 **)&data, &len)) {
		return;
	}

	tmp = os_realloc(data, len + 1);
	if (!tmp) {
		os_free(data);
		return;
	}

	data = tmp;
	data[len] = '\0';

	for (line = strtok_r(data, "\r\n", &save);
	     line;
	     line = strtok_r(NULL, "\r\n", &save)) {
		char *eq, *val;

		if (!cpro) {
			cpro = !os_strcmp(line, "cpro");
			continue;
		}

		if (!os_strncmp(line, "-----", 5)) {
			break;
		}

		eq = os_strchr(line, '=');
		if (!eq) {
			continue;
		}

		*eq++ = '\0';
		val = eq;

		while (*val == ' ' || *val == '\t') {
			val++;
		}

		if (!os_strcmp(line, "pin") && !cfg->pin) {
			cfg->pin = os_strdup(val);
		} else if (!os_strcmp(line, "domain_match") &&
			   !cfg->domain_match) {
			cfg->domain_match = os_strdup(val);
		}
	}

	os_free(data);
}

static int get_cert_hash_from_file(const char *path, u8 hash[CSP_CERT_HASH_LEN])
{
  DWORD file_len = 0;
  u8 *file = NULL;
  const char *pos;
  PCCERT_CONTEXT cert = NULL;
  int is_pem = 0;
  int ret = -1;
  char thumbprint_hex[CSP_CERT_HASH_LEN * 2 + 1] = "";

  if (!path || read_file(path, &file, &file_len)) {
    wpa_printf(MSG_INFO, "CryptoPro: event=read_client_cert status=read_failed path='%s'",
               path ? path : "(null)");
    return -1;
  }

  pos = os_strstr((const char *) file, "-----BEGIN CERTIFICATE-----");
  if (pos) {
    const char *end = os_strstr(pos, "-----END CERTIFICATE-----");
    DWORD block_len;
    DWORD der_len = 0;
    u8 *der = NULL;

    is_pem = 1;
    if (!end)
      goto out;
    end += 25;
    block_len = (DWORD) (end - pos);

    if (CryptStringToBinaryA(pos, block_len,
                             CRYPT_STRING_BASE64HEADER, NULL, &der_len,
                             NULL, NULL)) {
      der = os_malloc(der_len);
      if (der && CryptStringToBinaryA(pos, block_len,
                                      CRYPT_STRING_BASE64HEADER, der,
                                      &der_len, NULL, NULL)) {
        cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            der, der_len);
      }
      os_free(der);
    }
  } else {
    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        file, file_len);
  }

  if (cert) {
    DWORD h_len = CSP_CERT_HASH_LEN;
    if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
                                          hash, &h_len) &&
        h_len == CSP_CERT_HASH_LEN) {
      ret = 0;
      format_hex(hash, CSP_CERT_HASH_LEN, thumbprint_hex, sizeof(thumbprint_hex));
    }
    CertFreeCertificateContext(cert);
  }

out:
  wpa_printf(MSG_INFO,
             "CryptoPro: event=read_client_cert path='%s' format=%s thumbprint=%s status=%s",
             path, is_pem ? "pem" : "der", thumbprint_hex, ret == 0 ? "success" : "failed");
  os_free(file);
  return ret;
}

static int load_ca_store(struct tls_connection *conn, const char *path)
{
  DWORD file_len = 0;
  u8 *file = NULL;
  const char *pos;
  int ret = -1;
  int cert_count = 0;

  wpa_printf(MSG_INFO, "CryptoPro: event=load_ca_store path='%s'",
             path ? path : "(null)");
  if (!path || read_file(path, &file, &file_len))
    goto out;

  conn->ca_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                 CERT_STORE_CREATE_NEW_FLAG, NULL);
  if (!conn->ca_store)
    goto out;

  pos = (const char *) file;
  while ((pos = os_strstr(pos, "-----BEGIN CERTIFICATE-----"))) {
    const char *end = os_strstr(pos, "-----END CERTIFICATE-----");
    DWORD block_len;
    DWORD der_len = 0;
    u8 *der = NULL;
    PCCERT_CONTEXT cert = NULL;

    if (!end)
      break;
    end += 25;
    block_len = (DWORD) (end - pos);

    if (CryptStringToBinaryA(pos, block_len,
                             CRYPT_STRING_BASE64HEADER, NULL, &der_len,
                             NULL, NULL)) {
      der = os_malloc(der_len);
      if (der && CryptStringToBinaryA(pos, block_len,
                                      CRYPT_STRING_BASE64HEADER, der,
                                      &der_len, NULL, NULL)) {
        cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            der, der_len);
        if (cert) {
          if (CertAddCertificateContextToStore(conn->ca_store, cert,
                                               CERT_STORE_ADD_ALWAYS, NULL))
            cert_count++;
          CertFreeCertificateContext(cert);
        }
      }
      os_free(der);
    }
    pos = end;
  }

  if (cert_count == 0) {
    PCCERT_CONTEXT cert = CertCreateCertificateContext(
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, file, file_len);
    if (cert) {
      if (CertAddCertificateContextToStore(conn->ca_store, cert,
                                           CERT_STORE_ADD_ALWAYS, NULL))
        cert_count++;
      CertFreeCertificateContext(cert);
    }
  }

  if (cert_count > 0)
    ret = 0;

out:
  wpa_printf(MSG_INFO, "CryptoPro: event=load_ca_store path='%s' cert_count=%d status=%s",
             path ? path : "(null)", cert_count, ret == 0 ? "success" : "failed");
  if (ret)
    wpa_printf(MSG_INFO, "CryptoPro: event=load_ca_store error=0x%08lx",
               (unsigned long) GetLastError());
  os_free(file);
  return ret;
}

static int find_hello_random(const u8 *buf, size_t len, u8 type, u8 random[32])
{
  size_t off = 0;

  while (off + 5 <= len) {
    size_t rec_len = WPA_GET_BE16(buf + off + 3);
    size_t pos;
    size_t end;

    if (off + 5 + rec_len > len)
      return -1;
    if (buf[off] != 22) {
      off += 5 + rec_len;
      continue;
    }

    pos = off + 5;
    end = pos + rec_len;
    while (pos + 4 <= end) {
      size_t msg_len = WPA_GET_BE24(buf + pos + 1);

      if (pos + 4 + msg_len > end)
        break;
      if (buf[pos] == type && msg_len >= 34) {
        os_memcpy(random, buf + pos + 6, 32);
        return 0;
      }
      pos += 4 + msg_len;
    }
    off += 5 + rec_len;
  }

  return -1;
}

static struct wpabuf * copy_token(struct tls_connection *conn, SecBuffer *out)
{
  struct wpabuf *buf;

  if (!out->pvBuffer || !out->cbBuffer)
    return wpabuf_alloc(0);

  if (!conn->have_client_random &&
      !find_hello_random(out->pvBuffer, out->cbBuffer, 1,
                         conn->client_random))
    conn->have_client_random = 1;

  buf = wpabuf_alloc_copy(out->pvBuffer, out->cbBuffer);
  conn->ctx->sspi->FreeContextBuffer(out->pvBuffer);
  out->pvBuffer = NULL;
  return buf;
}

static int acquire_credentials(struct tls_connection *conn)
{
  SCHANNEL_CRED sc;
  TimeStamp expiry;
  SECURITY_STATUS status;

  os_memset(&sc, 0, sizeof(sc));
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.cCreds = 1;
  sc.paCred = &conn->cert;
  conn->root_store = CertOpenSystemStoreA(0, "ROOT");
  if (!conn->root_store) {
    wpa_printf(MSG_INFO, "CryptoPro: event=open_store store=ROOT status=failed error=0x%08lx",
               (unsigned long) GetLastError());
    return -1;
  }
  wpa_printf(MSG_INFO, "CryptoPro: event=open_store store=ROOT status=success");
  sc.hRootStore = conn->root_store;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
  sc.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
  wpa_printf(MSG_INFO, "CryptoPro: event=acquire_credentials protocol=TLSv1.2 direction=outbound");

  status = conn->ctx->sspi->AcquireCredentialsHandleA(
    NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL,
    &conn->cred, &expiry);
  if (status != SEC_E_OK) {
    csp_error(conn, "AcquireCredentialsHandle", status);
    return -1;
  }

  conn->have_cred = 1;
  wpa_printf(MSG_INFO, "CryptoPro: event=acquire_credentials status=success");
  return 0;
}

void * tls_init(const struct tls_config *conf)
{
  struct tls_context *ctx;
  INIT_SECURITY_INTERFACE init = InitSecurityInterfaceA;

  ctx = os_zalloc(sizeof(*ctx));
  if (!ctx)
    return NULL;
  if (conf)
    os_memcpy(&ctx->conf, conf, sizeof(*conf));
  ctx->sspi = init();
  if (!ctx->sspi) {
    os_free(ctx);
    return NULL;
  }

  wpa_printf(MSG_INFO, "CryptoPro: event=tls_init status=success backend=SSPI");
  return ctx;
}

void tls_deinit(void *tls_ctx)
{
  os_free(tls_ctx);
}

int tls_get_errors(void *tls_ctx)
{
  struct tls_context *ctx = tls_ctx;
  int errors;

  if (!ctx)
    return 1;
  errors = ctx->errors;
  ctx->errors = 0;
  return errors;
}

struct tls_connection * tls_connection_init(void *tls_ctx)
{
  struct tls_connection *conn;

  if (!tls_ctx)
    return NULL;
  conn = os_zalloc(sizeof(*conn));
  if (conn)
    conn->ctx = tls_ctx;
  return conn;
}

void tls_connection_deinit(void *tls_ctx, struct tls_connection *conn)
{
  if (!conn)
    return;
  if (conn->have_ctxt)
    conn->ctx->sspi->DeleteSecurityContext(&conn->ctxt);
  if (conn->have_cred)
    conn->ctx->sspi->FreeCredentialsHandle(&conn->cred);
  if (conn->cert)
    CertFreeCertificateContext(conn->cert);
  if (conn->ca_store)
    CertCloseStore(conn->ca_store, 0);
  if (conn->root_store)
    CertCloseStore(conn->root_store, 0);
  os_free(conn->server_name);
  bin_clear_free(conn, sizeof(*conn));
}

int tls_connection_established(void *tls_ctx, struct tls_connection *conn)
{
  return conn && conn->established;
}

char * tls_connection_peer_serial_num(void *tls_ctx,
                                      struct tls_connection *conn)
{
  return NULL;
}

int tls_connection_shutdown(void *tls_ctx, struct tls_connection *conn)
{
  if (!conn)
    return -1;
  if (conn->have_ctxt) {
    conn->ctx->sspi->DeleteSecurityContext(&conn->ctxt);
    conn->have_ctxt = 0;
  }
  conn->established = 0;
  conn->failed = 0;
  conn->own_cert_used = 0;
  conn->have_client_random = 0;
  conn->have_server_random = 0;
  return 0;
}

int tls_connection_set_params(void *tls_ctx, struct tls_connection *conn,
                              const struct tls_connection_params *params)
{
  u8 cert_hash[CSP_CERT_HASH_LEN];
  struct cpro_key_config key_cfg;
  const char *pin;

  if (!conn || !params || !params->client_cert) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=failed reason='client_cert missing'");
    return -1;
  }

  wpa_printf(MSG_INFO,
             "CryptoPro: event=set_params client_cert='%s' private_key='%s' ca_cert='%s'",
             params->client_cert ? params->client_cert : "",
             params->private_key ? params->private_key : "",
             params->ca_cert ? params->ca_cert : "");

  if (get_cert_hash_from_file(params->client_cert, cert_hash) != 0) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=failed reason='failed to read client_cert'");
    return -1;
  }

  conn->cert = find_cert(cert_hash);
  if (!conn->cert) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=failed reason='certificate not found in MY store'");
    return -1;
  }
  log_certificate_details(conn->cert);
  if (bind_certificate_provider(conn->cert))
    return -1;

  parse_cpro_key_file(params->private_key, &key_cfg);

  pin = (key_cfg.pin && key_cfg.pin[0]) ? key_cfg.pin : "123456";

  if (set_certificate_pin(conn->cert, pin)) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=failed reason='failed to set certificate PIN'");
    os_free(key_cfg.pin);
    os_free(key_cfg.domain_match);
    return -1;
  }

  if (key_cfg.domain_match && key_cfg.domain_match[0])
    conn->server_name = os_strdup(key_cfg.domain_match);
  else
    conn->server_name = NULL;

  wpa_printf(MSG_INFO,
             "CryptoPro: event=configure_domain expected_domain='%s' verify_domain=%s",
             conn->server_name ? conn->server_name : "",
             conn->server_name ? "yes" : "no");

  os_free(key_cfg.pin);
  os_free(key_cfg.domain_match);

  if (load_ca_store(conn, params->ca_cert)) {
    wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=failed reason='failed to load ca_cert'");
    return -1;
  }
  if (acquire_credentials(conn))
    return -1;

  wpa_printf(MSG_INFO, "CryptoPro: event=set_params status=success");
  return 0;
}

int tls_global_set_params(void *tls_ctx,
                          const struct tls_connection_params *params)
{
  return -1;
}

int tls_global_set_verify(void *tls_ctx, int check_crl, int strict)
{
  return 0;
}

int tls_connection_set_verify(void *tls_ctx, struct tls_connection *conn,
                              int verify_peer, unsigned int flags,
                              const u8 *session_ctx, size_t session_ctx_len)
{
  return verify_peer == 1 ? 0 : -1;
}

int tls_connection_get_random(void *tls_ctx, struct tls_connection *conn,
                              struct tls_random *data)
{
  if (!conn || !data || !conn->have_client_random ||
      !conn->have_server_random)
    return -1;
  data->client_random = conn->client_random;
  data->client_random_len = sizeof(conn->client_random);
  data->server_random = conn->server_random;
  data->server_random_len = sizeof(conn->server_random);
  return 0;
}

int tls_connection_export_key(void *tls_ctx, struct tls_connection *conn,
                              const char *label, const u8 *context,
                              size_t context_len, u8 *out, size_t out_len)
{
  SecPkgContext_EapKeyBlock keys;
  SECURITY_STATUS status;

  if (!conn || !conn->established || !label ||
      os_strcmp(label, "client EAP encryption") || context || context_len ||
      !out || out_len > sizeof(keys.rgbKeys))
    return -1;

  os_memset(&keys, 0, sizeof(keys));
  status = conn->ctx->sspi->QueryContextAttributesA(
    &conn->ctxt, SECPKG_ATTR_EAP_KEY_BLOCK, &keys);
  if (status != SEC_E_OK) {
    csp_error(conn, "SECPKG_ATTR_EAP_KEY_BLOCK", status);
    return -1;
  }
  os_memcpy(out, keys.rgbKeys, out_len);
  forced_memzero(&keys, sizeof(keys));
  wpa_printf(MSG_INFO, "CryptoPro: event=export_key label='%s' key_length=%lu status=success",
             label, (unsigned long) out_len);
  return 0;
}

int tls_connection_get_eap_fast_key(void *tls_ctx,
                                    struct tls_connection *conn,
                                    u8 *out, size_t out_len)
{
  return -1;
}

static void update_connection_info(struct tls_connection *conn)
{
  SecPkgContext_CipherInfo cipher;
  PCCERT_CONTEXT local = NULL;
  SECURITY_STATUS status;

  os_memset(&cipher, 0, sizeof(cipher));
  cipher.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
  status = conn->ctx->sspi->QueryContextAttributesA(
    &conn->ctxt, SECPKG_ATTR_CIPHER_INFO, &cipher);
  if (status == SEC_E_OK)
    conn->cipher_suite = (u16) cipher.dwCipherSuite;

  status = conn->ctx->sspi->QueryContextAttributesA(
    &conn->ctxt, SECPKG_ATTR_LOCAL_CERT_CONTEXT, &local);
  if (status == SEC_E_OK && local) {
    conn->own_cert_used = local->cbCertEncoded == conn->cert->cbCertEncoded &&
      !os_memcmp(local->pbCertEncoded, conn->cert->pbCertEncoded,
                 conn->cert->cbCertEncoded);
    CertFreeCertificateContext(local);
  }
}

static int verify_server_cert(struct tls_connection *conn)
{
  PCCERT_CONTEXT remote = NULL;
  PCCERT_CONTEXT ca = NULL;
  SECURITY_STATUS status;
  char remote_subj[256] = "";
  char remote_issuer[256] = "";
  char ca_subj[256] = "";
  char dns[256];
  int ret = -1;

  status = conn->ctx->sspi->QueryContextAttributesA(
    &conn->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote);
  if (status != SEC_E_OK || !remote) {
    csp_error(conn, "SECPKG_ATTR_REMOTE_CERT_CONTEXT", status);
    goto out;
  }

  CertGetNameStringA(remote, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                     remote_subj, sizeof(remote_subj));
  CertGetNameStringA(remote, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL,
                     remote_issuer, sizeof(remote_issuer));
  wpa_printf(MSG_INFO,
             "CryptoPro: event=verify_server_cert remote_subject='%s' remote_issuer='%s'",
             remote_subj, remote_issuer);

  if (CertVerifyTimeValidity(NULL, remote->pCertInfo) != 0) {
    wpa_printf(MSG_INFO, "CryptoPro: event=verify_server_cert status=expired");
    goto out;
  }

  while ((ca = CertEnumCertificatesInStore(conn->ca_store, ca))) {
    if (CertCompareCertificateName(X509_ASN_ENCODING,
                                   &remote->pCertInfo->Issuer,
                                   &ca->pCertInfo->Subject) &&
        CryptVerifyCertificateSignatureEx(
          0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *) remote,
          CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *) ca, 0, NULL)) {
      break;
    }
  }

  if (!ca) {
    wpa_printf(MSG_INFO,
               "CryptoPro: event=verify_server_cert status=signature_failed error=0x%08lx",
               (unsigned long) GetLastError());
    goto out;
  }

  CertGetNameStringA(ca, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                     ca_subj, sizeof(ca_subj));
  wpa_printf(MSG_INFO,
             "CryptoPro: event=verify_server_cert status=signature_ok ca_subject='%s'",
             ca_subj);

  if (conn->server_name) {
    dns[0] = '\0';
    CertGetNameStringA(remote, CERT_NAME_DNS_TYPE, 0, NULL, dns, sizeof(dns));
    wpa_printf(MSG_INFO,
               "CryptoPro: event=verify_server_domain expected='%s' cert_dns='%s'",
               conn->server_name, dns[0] ? dns : "<none>");
    if (!dns[0] || os_strcasecmp(dns, conn->server_name)) {
      wpa_printf(MSG_INFO,
                 "CryptoPro: event=verify_server_domain status=mismatch expected='%s' cert_dns='%s'",
                 conn->server_name, dns[0] ? dns : "<none>");
      goto out;
    }
    wpa_printf(MSG_INFO,
               "CryptoPro: event=verify_server_domain status=match expected='%s' cert_dns='%s'",
               conn->server_name, dns);
  } else {
    wpa_printf(MSG_INFO,
               "CryptoPro: event=verify_server_domain status=skipped reason='domain_match not configured'");
  }

  ret = 0;

out:
  if (ca)
    CertFreeCertificateContext(ca);
  if (remote)
    CertFreeCertificateContext(remote);
  if (ret) {
    conn->failed = 1;
    conn->ctx->errors++;
  }
  return ret;
}

struct wpabuf * tls_connection_handshake(void *tls_ctx,
                                         struct tls_connection *conn,
                                         const struct wpabuf *in_data,
                                         struct wpabuf **appl_data)
{
  SecBuffer in[2];
  SecBufferDesc in_desc;
  SecBuffer out;
  SecBufferDesc out_desc;
  ULONG out_flags = 0;
  TimeStamp expiry;
  SECURITY_STATUS status;
  DWORD flags;
  struct wpabuf *ret;

  if (appl_data)
    *appl_data = NULL;
  if (!conn || !conn->have_cred || conn->failed)
    return NULL;

  wpa_printf(MSG_INFO, "CryptoPro: event=handshake_step state=%s input_bytes=%lu",
             conn->have_ctxt ? "continue" : "start",
             (unsigned long) (in_data ? wpabuf_len(in_data) : 0));

  flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
          ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
          ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
  os_memset(&out, 0, sizeof(out));
  out.BufferType = SECBUFFER_TOKEN;
  out_desc.ulVersion = SECBUFFER_VERSION;
  out_desc.cBuffers = 1;
  out_desc.pBuffers = &out;

  if (!conn->have_ctxt) {
    status = conn->ctx->sspi->InitializeSecurityContextA(
      &conn->cred, NULL, conn->server_name, flags, 0, SECURITY_NATIVE_DREP,
      NULL, 0, &conn->ctxt, &out_desc, &out_flags, &expiry);
    if (status == SEC_I_CONTINUE_NEEDED)
      conn->have_ctxt = 1;
  } else {
    os_memset(in, 0, sizeof(in));
    in[0].BufferType = SECBUFFER_TOKEN;
    in[0].pvBuffer = (void *) wpabuf_head(in_data);
    in[0].cbBuffer = (ULONG) wpabuf_len(in_data);
    in[1].BufferType = SECBUFFER_EMPTY;
    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers = 2;
    in_desc.pBuffers = in;

    if (!conn->have_server_random &&
        !find_hello_random(wpabuf_head(in_data), wpabuf_len(in_data), 2,
                           conn->server_random))
      conn->have_server_random = 1;

    status = conn->ctx->sspi->InitializeSecurityContextA(
      &conn->cred, &conn->ctxt, NULL, flags, 0, SECURITY_NATIVE_DREP,
      &in_desc, 0, NULL, &out_desc, &out_flags, &expiry);
  }

  wpa_printf(MSG_INFO, "CryptoPro: event=init_security_context status=0x%08lx output_bytes=%lu",
             (unsigned long) status,
             (unsigned long) out.cbBuffer);

  if ((status == SEC_I_COMPLETE_NEEDED ||
       status == SEC_I_COMPLETE_AND_CONTINUE) &&
      conn->ctx->sspi->CompleteAuthToken)
    conn->ctx->sspi->CompleteAuthToken(&conn->ctxt, &out_desc);

  if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED &&
      status != SEC_I_COMPLETE_NEEDED &&
      status != SEC_I_COMPLETE_AND_CONTINUE) {
    csp_error(conn, "InitializeSecurityContext", status);
    ret = copy_token(conn, &out);
    if (ret && wpabuf_len(ret))
      conn->write_alerts++;
    return ret;
  }

  if (status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED) {
    if (verify_server_cert(conn)) {
      ret = copy_token(conn, &out);
      return ret;
    }
    conn->established = 1;
    update_connection_info(conn);
    wpa_printf(MSG_INFO,
               "CryptoPro: event=handshake_complete protocol=TLSv1.2 cipher_suite=0x%04x own_cert_used=%s",
               conn->cipher_suite,
               conn->own_cert_used ? "yes" : "no");
  }

  return copy_token(conn, &out);
}

struct wpabuf * tls_connection_handshake2(void *tls_ctx,
                                          struct tls_connection *conn,
                                          const struct wpabuf *in_data,
                                          struct wpabuf **appl_data,
                                          int *more_data_needed)
{
  if (more_data_needed)
    *more_data_needed = 0;
  return tls_connection_handshake(tls_ctx, conn, in_data, appl_data);
}

struct wpabuf * tls_connection_server_handshake(void *tls_ctx,
                                                struct tls_connection *conn,
                                                const struct wpabuf *in_data,
                                                struct wpabuf **appl_data)
{
  return NULL;
}

struct wpabuf * tls_connection_encrypt(void *tls_ctx,
                                       struct tls_connection *conn,
                                       const struct wpabuf *in_data)
{
  return NULL;
}

struct wpabuf * tls_connection_decrypt(void *tls_ctx,
                                       struct tls_connection *conn,
                                       const struct wpabuf *in_data)
{
  return NULL;
}

struct wpabuf * tls_connection_decrypt2(void *tls_ctx,
                                        struct tls_connection *conn,
                                        const struct wpabuf *in_data,
                                        int *more_data_needed)
{
  if (more_data_needed)
    *more_data_needed = 0;
  return NULL;
}

int tls_connection_resumed(void *tls_ctx, struct tls_connection *conn)
{
  return 0;
}

int tls_connection_set_cipher_list(void *tls_ctx,
                                   struct tls_connection *conn, u8 *ciphers)
{
  return -1;
}

int tls_get_version(void *tls_ctx, struct tls_connection *conn,
                    char *buf, size_t buflen)
{
  if (!conn || !conn->established)
    return -1;
  return os_snprintf(buf, buflen, "TLSv1.2") >= (int) buflen ? -1 : 0;
}

int tls_get_cipher(void *tls_ctx, struct tls_connection *conn,
                   char *buf, size_t buflen)
{
  int ret;

  if (!conn || !conn->established)
    return -1;
  ret = os_snprintf(buf, buflen, "GOST-TLS1.2-0x%04x", conn->cipher_suite);
  return ret < 0 || (size_t) ret >= buflen ? -1 : 0;
}

int tls_connection_enable_workaround(void *tls_ctx,
                                     struct tls_connection *conn)
{
  return 0;
}

int tls_connection_client_hello_ext(void *tls_ctx,
                                    struct tls_connection *conn, int ext_type,
                                    const u8 *data, size_t data_len)
{
  return -1;
}

int tls_connection_get_failed(void *tls_ctx, struct tls_connection *conn)
{
  return conn ? conn->failed : 1;
}

int tls_connection_get_read_alerts(void *tls_ctx,
                                   struct tls_connection *conn)
{
  return conn ? conn->read_alerts : 0;
}

int tls_connection_get_write_alerts(void *tls_ctx,
                                    struct tls_connection *conn)
{
  return conn ? conn->write_alerts : 0;
}

int tls_connection_set_session_ticket_cb(void *tls_ctx,
                                         struct tls_connection *conn,
                                         tls_session_ticket_cb cb, void *ctx)
{
  return -1;
}

void tls_connection_set_log_cb(struct tls_connection *conn,
                               void (*log_cb)(void *ctx, const char *msg),
                               void *ctx)
{
}

void tls_connection_set_test_flags(struct tls_connection *conn, u32 flags)
{
}

int tls_get_library_version(char *buf, size_t buf_len)
{
  int ret = os_snprintf(buf, buf_len, "CryptoPro CSP SSPI");
  return ret < 0 || (size_t) ret >= buf_len ? -1 : ret;
}

void tls_connection_set_success_data(struct tls_connection *conn,
                                     struct wpabuf *data)
{
  wpabuf_free(data);
}

void tls_connection_set_success_data_resumed(struct tls_connection *conn)
{
}

const struct wpabuf *
tls_connection_get_success_data(struct tls_connection *conn)
{
  return NULL;
}

void tls_connection_remove_session(struct tls_connection *conn)
{
}

int tls_get_tls_unique(struct tls_connection *conn, u8 *buf, size_t max_len)
{
  return -1;
}

u16 tls_connection_get_cipher_suite(struct tls_connection *conn)
{
  return conn ? conn->cipher_suite : 0;
}

const char * tls_connection_get_peer_subject(struct tls_connection *conn)
{
  return NULL;
}

bool tls_connection_get_own_cert_used(struct tls_connection *conn)
{
  return conn && conn->own_cert_used;
}

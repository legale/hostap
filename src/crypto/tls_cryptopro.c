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

#define CSP_CERT_PREFIX "csp:uMy:"
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
  wpa_printf(MSG_INFO, "CryptoPro: %s failed: 0x%08lx", op,
             (unsigned long) status);
  conn->failed = 1;
  conn->ctx->errors++;
}

static int hex_value(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int parse_cert_id(const char *id, u8 hash[CSP_CERT_HASH_LEN])
{
  const char *pos;
  size_t i;

  if (!id || os_strncmp(id, CSP_CERT_PREFIX, os_strlen(CSP_CERT_PREFIX)))
    return -1;

  pos = id + os_strlen(CSP_CERT_PREFIX);
  if (os_strlen(pos) != CSP_CERT_HASH_LEN * 2)
    return -1;

  for (i = 0; i < CSP_CERT_HASH_LEN; i++) {
    int hi = hex_value(pos[i * 2]);
    int lo = hex_value(pos[i * 2 + 1]);

    if (hi < 0 || lo < 0)
      return -1;
    hash[i] = (u8) ((hi << 4) | lo);
  }

  return 0;
}

static PCCERT_CONTEXT find_cert(const u8 wanted[CSP_CERT_HASH_LEN])
{
  HCERTSTORE store;
  PCCERT_CONTEXT cert = NULL;
  PCCERT_CONTEXT found = NULL;

  store = CertOpenSystemStoreA(0, "MY");
  if (!store) {
    wpa_printf(MSG_INFO, "CryptoPro: open MY store failed: 0x%08lx",
               (unsigned long) GetLastError());
    return NULL;
  }
  wpa_printf(MSG_INFO, "CryptoPro: searching MY store for requested client cert");

  while ((cert = CertEnumCertificatesInStore(store, cert))) {
    DWORD hash_len = CSP_CERT_HASH_LEN;
    u8 hash[CSP_CERT_HASH_LEN];

    if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
                                           hash, &hash_len) ||
        hash_len != CSP_CERT_HASH_LEN ||
        os_memcmp(hash, wanted, sizeof(hash)))
      continue;

    if (CertVerifyTimeValidity(NULL, cert->pCertInfo) != 0) {
      wpa_printf(MSG_INFO, "CryptoPro: requested client cert is expired");
      break;
    }

    found = CertDuplicateCertificateContext(cert);
    break;
  }

  if (cert)
    CertFreeCertificateContext(cert);
  CertCloseStore(store, 0);
  wpa_printf(MSG_INFO, "CryptoPro: client cert store search result: %s",
             found ? "found" : "not found");
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
    wpa_printf(MSG_INFO, "CryptoPro: client certificate PIN not configured");
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
  os_free(info);
  wpa_printf(MSG_INFO, "CryptoPro: client certificate PIN property: %s",
             ok ? "set" : "failed");
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
  wpa_printf(MSG_INFO, "CryptoPro: client cert subject=%s", subject);

  if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
                                        NULL, &info_len)) {
    info = os_malloc(info_len);
    if (info && CertGetCertificateContextProperty(cert,
        CERT_KEY_PROV_INFO_PROP_ID, info, &info_len)) {
      wpa_printf(MSG_INFO,
                 "CryptoPro: cert provider=%ls type=%lu key_spec=%lu",
                 info->pwszProvName ? info->pwszProvName : L"(none)",
                 (unsigned long) info->dwProvType,
                 (unsigned long) info->dwKeySpec);
    }
  }

  if (!CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_SILENT_FLAG,
                                         NULL, &key, &key_spec, &free_key)) {
    wpa_printf(MSG_INFO,
               "CryptoPro: private key acquire failed: 0x%08lx",
               (unsigned long) GetLastError());
    os_free(info);
    return;
  }

  wpa_printf(MSG_INFO, "CryptoPro: private key acquired key_spec=%lu",
             (unsigned long) key_spec);
  if (CryptGetUserKey((HCRYPTPROV) key, AT_KEYEXCHANGE, &exchange_key)) {
    wpa_printf(MSG_INFO, "CryptoPro: exchange key: available");
    CryptDestroyKey(exchange_key);
  } else {
    wpa_printf(MSG_INFO, "CryptoPro: exchange key: unavailable, error=0x%08lx",
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
  wpa_printf(MSG_INFO, "CryptoPro: certificate bound to provider=%ls",
             provider);
  ret = 0;

out:
  if (ret)
    wpa_printf(MSG_INFO, "CryptoPro: certificate provider binding failed: "
               "0x%08lx", (unsigned long) GetLastError());
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

static int load_ca_store(struct tls_connection *conn, const char *path)
{
  PCCERT_CONTEXT cert = NULL;
  DWORD der_len = 0;
  DWORD file_len;
  u8 *file = NULL;
  u8 *der = NULL;
  int ret = -1;

  wpa_printf(MSG_INFO, "CryptoPro: loading CA certificate: %s",
             path ? path : "(null)");
  if (!path || read_file(path, &file, &file_len))
    goto out;

  if (CryptStringToBinaryA((char *) file, file_len,
                           CRYPT_STRING_BASE64HEADER, NULL, &der_len,
                           NULL, NULL)) {
    der = os_malloc(der_len);
    if (!der || !CryptStringToBinaryA((char *) file, file_len,
                                      CRYPT_STRING_BASE64HEADER, der,
                                      &der_len, NULL, NULL))
      goto out;
  } else {
    der = os_memdup(file, file_len);
    der_len = file_len;
    if (!der)
      goto out;
  }

  cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                      der, der_len);
  if (!cert)
    goto out;

  conn->ca_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                 CERT_STORE_CREATE_NEW_FLAG, NULL);
  if (!conn->ca_store)
    goto out;

  if (!CertAddCertificateContextToStore(conn->ca_store, cert,
                                        CERT_STORE_ADD_ALWAYS, NULL))
    goto out;

  ret = 0;
  wpa_printf(MSG_INFO, "CryptoPro: CA certificate loaded into memory store");

out:
  if (ret)
    wpa_printf(MSG_INFO, "CryptoPro: CA certificate load failed: 0x%08lx",
               (unsigned long) GetLastError());
  if (cert)
    CertFreeCertificateContext(cert);
  os_free(der);
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
    wpa_printf(MSG_INFO, "CryptoPro: open ROOT store failed: 0x%08lx",
               (unsigned long) GetLastError());
    return -1;
  }
  wpa_printf(MSG_INFO, "CryptoPro: using system ROOT store for SSPI");
  sc.hRootStore = conn->root_store;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
  sc.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
  wpa_printf(MSG_INFO, "CryptoPro: acquiring outbound SSPI credentials");

  status = conn->ctx->sspi->AcquireCredentialsHandleA(
    NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL,
    &conn->cred, &expiry);
  if (status != SEC_E_OK) {
    csp_error(conn, "AcquireCredentialsHandle", status);
    return -1;
  }

  conn->have_cred = 1;
  wpa_printf(MSG_INFO, "CryptoPro: outbound SSPI credentials acquired");
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

  wpa_printf(MSG_INFO, "CryptoPro: SSPI TLS backend initialized");
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

  if (!conn || !params || parse_cert_id(params->client_cert, cert_hash) ||
      parse_cert_id(params->private_key, cert_hash)) {
    wpa_printf(MSG_INFO, "CryptoPro: invalid certificate reference");
    return -1;
  }
  wpa_printf(MSG_INFO, "CryptoPro: configuring client TLS parameters");
  if (os_strcmp(params->client_cert, params->private_key)) {
    wpa_printf(MSG_INFO, "CryptoPro: client_cert and private_key differ");
    return -1;
  }
  if (params->pin) {
    wpa_printf(MSG_INFO, "CryptoPro: pin is not supported");
    return -1;
  }
  if (!params->domain_match || os_strchr(params->domain_match, ';')) {
    wpa_printf(MSG_INFO, "CryptoPro: one domain_match value is required");
    return -1;
  }

  conn->cert = find_cert(cert_hash);
  if (!conn->cert) {
    wpa_printf(MSG_INFO, "CryptoPro: certificate with private key not found");
    return -1;
  }
  log_certificate_details(conn->cert);
  if (bind_certificate_provider(conn->cert))
    return -1;
  if (set_certificate_pin(conn->cert, params->private_key_passwd)) {
    wpa_printf(MSG_INFO, "CryptoPro: failed to set certificate PIN");
    return -1;
  }
  conn->server_name = os_strdup(params->domain_match);
  if (!conn->server_name || load_ca_store(conn, params->ca_cert)) {
    wpa_printf(MSG_INFO, "CryptoPro: failed to load ca_cert");
    return -1;
  }
  if (acquire_credentials(conn))
    return -1;

  wpa_printf(MSG_INFO, "CryptoPro: client certificate selected");
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
  wpa_printf(MSG_INFO, "CryptoPro: EAP key block available (%lu bytes)",
             (unsigned long) out_len);
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
  char dns[256];
  int ret = -1;

  status = conn->ctx->sspi->QueryContextAttributesA(
    &conn->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote);
  if (status != SEC_E_OK || !remote) {
    csp_error(conn, "SECPKG_ATTR_REMOTE_CERT_CONTEXT", status);
    goto out;
  }

  ca = CertEnumCertificatesInStore(conn->ca_store, NULL);
  if (!ca) {
    wpa_printf(MSG_INFO, "CryptoPro: ca_cert store is empty");
    goto out;
  }

  if (CertVerifyTimeValidity(NULL, remote->pCertInfo) != 0) {
    wpa_printf(MSG_INFO, "CryptoPro: server certificate is not valid now");
    goto out;
  }

  if (!CertCompareCertificateName(X509_ASN_ENCODING,
                                  &remote->pCertInfo->Issuer,
                                  &ca->pCertInfo->Subject)) {
    wpa_printf(MSG_INFO, "CryptoPro: server certificate issuer mismatch");
    goto out;
  }

  if (!CryptVerifyCertificateSignatureEx(
        0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, remote,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, ca, 0, NULL)) {
    wpa_printf(MSG_INFO, "CryptoPro: server certificate signature failed");
    goto out;
  }

  if (!CertGetNameStringA(remote, CERT_NAME_DNS_TYPE, 0, NULL, dns,
                          sizeof(dns)) ||
      os_strcasecmp(dns, conn->server_name)) {
    wpa_printf(MSG_INFO, "CryptoPro: server certificate name mismatch");
    goto out;
  }

  wpa_printf(MSG_INFO, "CryptoPro: server certificate verified");
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

  wpa_printf(MSG_INFO, "CryptoPro: TLS handshake step: %s, input=%lu bytes",
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

  wpa_printf(MSG_INFO, "CryptoPro: InitializeSecurityContext status=0x%08lx, "
             "output=%lu bytes",
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
               "CryptoPro: TLS 1.2 established, cipher suite 0x%04x",
               conn->cipher_suite);
    wpa_printf(MSG_INFO, "CryptoPro: own certificate used: %s",
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

/*
 * LTC Wallet - ESP32 secure key + settings storage
 * Stores encrypted 32-byte wallet key, optional settings JSON, and last 32 transactions in NVS.
 * Serial protocol (115200 baud, newline-terminated):
 *   PING  -> reply PONG (LED blinks while connection active)
 *   SAVE,<base64_password>,<hex64_key>[,<base64_settings>]  -> store; reply OK or ERR,msg
 *   LOAD,<base64_password>  -> reply KEY,<hex64> then SETTINGS,<base64> (if stored)
 *   ADD_TX,<address>,<sent|received>,<amount_ltc>,<timestamp_unix>  -> store tx; reply OK or ERR
 * Password: SHA256 hash stored for verify; key/settings encrypted AES-256-CBC.
 */

#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#define NVS_NAMESPACE "ltcwallet"
#define NVS_KEY_PWDHASH "ph"
#define NVS_KEY_BLOB    "enc"
#define NVS_KEY_SETTINGS "set"
#define SETTINGS_MAX    1024
#define TX_MAX          32
#define TX_ENTRY_LEN    120   // address|status|amount|timestamp (truncate if longer)

#define LED_PIN         2
#define PING_TIMEOUT_MS 12000  /* match PC PONG timeout (12s) so LED stays on */
#define LED_BLINK_MS    200

Preferences prefs;
unsigned long lastPingTime = 0;
unsigned long lastLedToggle = 0;
bool ledOn = false;

static void sha256(const uint8_t* in, size_t inLen, uint8_t* out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, in, inLen);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

static int base64Decode(const char* in, size_t inLen, uint8_t* out, size_t* outLen) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  int buf = 0, bits = 0;
  for (size_t i = 0; i < inLen; i++) {
    if (in[i] == '=') break;
    const char* p = strchr(tbl, in[i]);
    if (!p) continue;
    int v = (int)(p - tbl);
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o < *outLen) out[o++] = (uint8_t)((buf >> bits) & 0xFF);
    }
  }
  *outLen = o;
  return 0;
}

static void hexDecode(const char* hex, size_t hexLen, uint8_t* out, size_t outSize) {
  for (size_t i = 0, j = 0; i + 1 < hexLen && j < outSize; i += 2, j++) {
    uint8_t a = (hex[i] <= '9') ? (hex[i] - '0') : (hex[i] - 'A' + 10);
    if (hex[i] >= 'a') a = hex[i] - 'a' + 10;
    uint8_t b = (hex[i+1] <= '9') ? (hex[i+1] - '0') : (hex[i+1] - 'A' + 10);
    if (hex[i+1] >= 'a') b = hex[i+1] - 'a' + 10;
    out[j] = (a << 4) | b;
  }
}

static void hexEncode(const uint8_t* data, size_t len, char* out) {
  const char* h = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i*2]   = h[data[i] >> 4];
    out[i*2+1] = h[data[i] & 0x0F];
  }
  out[len*2] = '\0';
}

static size_t base64Encode(const uint8_t* in, size_t inLen, char* out, size_t outMax) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for (size_t i = 0; i < inLen && o + 4 <= outMax; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < inLen) v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < inLen) v |= in[i + 2];
    out[o++] = tbl[(v >> 18) & 63];
    out[o++] = tbl[(v >> 12) & 63];
    out[o++] = (i + 1 < inLen) ? tbl[(v >> 6) & 63] : '=';
    out[o++] = (i + 2 < inLen) ? tbl[v & 63] : '=';
  }
  out[o] = '\0';
  return o;
}

static void aes256CbcEncrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, (unsigned char*)iv, in, out);
  mbedtls_aes_free(&aes);
}

static void aes256CbcDecrypt(const uint8_t* key, uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, in, out);
  mbedtls_aes_free(&aes);
}

void cmdSave(String pwdB64, String hexKey, String settingsB64) {
  if (hexKey.length() != 64) {
    Serial.println("ERR,invalid key length");
    return;
  }
  uint8_t pwdBuf[128];
  size_t pwdLen = sizeof(pwdBuf);
  base64Decode(pwdB64.c_str(), pwdB64.length(), pwdBuf, &pwdLen);
  uint8_t keyHash[32];
  sha256(pwdBuf, pwdLen, keyHash);

  uint8_t plainKey[32];
  hexDecode(hexKey.c_str(), 64, plainKey, 32);

  uint8_t iv[16];
  for (int i = 0; i < 16; i++) iv[i] = (uint8_t)esp_random();
  uint8_t ct[32];
  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, 16);
  aes256CbcEncrypt(keyHash, ivCopy, plainKey, ct, 32);

  prefs.begin(NVS_NAMESPACE, false);
  if (!prefs.putBytes(NVS_KEY_PWDHASH, keyHash, 32)) {
    prefs.end();
    Serial.println("ERR,nvs write hash");
    return;
  }
  uint8_t blob[48];
  memcpy(blob, iv, 16);
  memcpy(blob + 16, ct, 32);
  if (!prefs.putBytes(NVS_KEY_BLOB, blob, 48)) {
    prefs.end();
    Serial.println("ERR,nvs write blob");
    return;
  }

  if (settingsB64.length() > 0) {
    uint8_t settingsBuf[SETTINGS_MAX];
    size_t setLen = sizeof(settingsBuf);
    base64Decode(settingsB64.c_str(), settingsB64.length(), settingsBuf, &setLen);
    if (setLen > 0 && setLen <= SETTINGS_MAX - 32) {
      size_t blockLen = ((setLen + 15) / 16) * 16;
      uint8_t padVal = (uint8_t)(blockLen - setLen);
      for (size_t i = setLen; i < blockLen; i++) settingsBuf[i] = padVal;
      for (int i = 0; i < 16; i++) iv[i] = (uint8_t)esp_random();
      memcpy(ivCopy, iv, 16);
      uint8_t setCt[SETTINGS_MAX];
      aes256CbcEncrypt(keyHash, ivCopy, settingsBuf, setCt, blockLen);
      uint8_t setBlob[SETTINGS_MAX];
      memcpy(setBlob, iv, 16);
      memcpy(setBlob + 16, setCt, blockLen);
      prefs.putBytes(NVS_KEY_SETTINGS, setBlob, 16 + blockLen);
    }
  } else {
    prefs.remove(NVS_KEY_SETTINGS);
  }
  prefs.end();
  Serial.println("OK");
}

void cmdLoad(String pwdB64) {
  prefs.begin(NVS_NAMESPACE, true);
  size_t hashLen = prefs.getBytesLength(NVS_KEY_PWDHASH);
  if (hashLen != 32) {
    prefs.end();
    Serial.println("ERR,no wallet stored");
    return;
  }
  uint8_t storedHash[32];
  prefs.getBytes(NVS_KEY_PWDHASH, storedHash, 32);
  uint8_t pwdBuf[128];
  size_t pwdLen = sizeof(pwdBuf);
  base64Decode(pwdB64.c_str(), pwdB64.length(), pwdBuf, &pwdLen);
  uint8_t keyHash[32];
  sha256(pwdBuf, pwdLen, keyHash);
  if (memcmp(keyHash, storedHash, 32) != 0) {
    prefs.end();
    Serial.println("ERR,wrong password");
    return;
  }
  size_t blobLen = prefs.getBytesLength(NVS_KEY_BLOB);
  if (blobLen != 48) {
    prefs.end();
    Serial.println("ERR,corrupt data");
    return;
  }
  uint8_t blob[48];
  prefs.getBytes(NVS_KEY_BLOB, blob, 48);
  uint8_t plainKey[32];
  aes256CbcDecrypt(keyHash, blob, blob + 16, plainKey, 32);
  char hexOut[65];
  hexEncode(plainKey, 32, hexOut);
  Serial.print("KEY,");
  Serial.println(hexOut);

  size_t setLen = prefs.getBytesLength(NVS_KEY_SETTINGS);
  if (setLen >= 32 && setLen <= SETTINGS_MAX) {
    uint8_t setBlob[SETTINGS_MAX];
    prefs.getBytes(NVS_KEY_SETTINGS, setBlob, setLen);
    prefs.end();
    size_t ctLen = setLen - 16;
    uint8_t setPlain[SETTINGS_MAX];
    aes256CbcDecrypt(keyHash, setBlob, setBlob + 16, setPlain, ctLen);
    uint8_t padVal = setPlain[ctLen - 1];
    if (padVal > 0 && padVal <= 16) ctLen -= padVal;
    char b64Out[700];
    base64Encode(setPlain, ctLen, b64Out, sizeof(b64Out));
    Serial.print("SETTINGS,");
    Serial.println(b64Out);
  } else {
    prefs.end();
  }
}

void cmdAddTx(String address, String status, String amount, String timestamp) {
  if (address.length() > 64) address = address.substring(0, 64);
  if (status != "sent" && status != "received") status = "sent";
  String entry = address + "|" + status + "|" + amount + "|" + timestamp;
  if (entry.length() > TX_ENTRY_LEN) entry = entry.substring(0, TX_ENTRY_LEN);
  prefs.begin(NVS_NAMESPACE, false);
  for (int i = TX_MAX - 2; i >= 0; i--) {
    String key = "tx" + String(i);
    String nextKey = "tx" + String(i + 1);
    String val = prefs.getString(key.c_str(), "");
    if (val.length() > 0) prefs.putString(nextKey.c_str(), val);
  }
  prefs.putString("tx0", entry);
  prefs.end();
  Serial.println("OK");
}

void cmdListTx() {
  prefs.begin(NVS_NAMESPACE, true);
  for (int i = 0; i < TX_MAX; i++) {
    String key = "tx" + String(i);
    String val = prefs.getString(key.c_str(), "");
    if (val.length() > 0) {
      Serial.print("TX,");
      Serial.println(val);
    }
  }
  prefs.end();
  Serial.println("OK");
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  Serial.begin(115200);
  delay(500);
  Serial.println("LTC_WALLET_READY");
}

#define BEACON_INTERVAL_MS 1000

void loop() {
  unsigned long now = millis();
  if (now - lastPingTime < PING_TIMEOUT_MS) {
    if (now - lastLedToggle >= LED_BLINK_MS) {
      ledOn = !ledOn;
      digitalWrite(LED_PIN, ledOn ? HIGH : LOW);
      lastLedToggle = now;
    }
  } else {
    digitalWrite(LED_PIN, LOW);
    ledOn = false;
  }
  static unsigned long lastBeacon = 0;
  if (now - lastBeacon >= BEACON_INTERVAL_MS) {
    Serial.print("ltc\n");
    lastBeacon = now;
  }
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (line.length() > 0) {
        if (line == "PING") {
          lastPingTime = millis();
          Serial.println("PONG");
        } else {
          int c1 = line.indexOf(',');
          if (c1 < 0) {
            Serial.println("ERR,invalid format");
          } else {
            String cmd = line.substring(0, c1);
            String rest = line.substring(c1 + 1);
            if (cmd == "SAVE") {
              int c2 = rest.indexOf(',');
              if (c2 < 0) Serial.println("ERR,SAVE needs password,key");
              else {
                String afterPwd = rest.substring(c2 + 1);
                int c3 = afterPwd.indexOf(',');
                if (c3 < 0) {
                  cmdSave(rest.substring(0, c2), afterPwd, "");
                } else {
                  cmdSave(rest.substring(0, c2), afterPwd.substring(0, c3), afterPwd.substring(c3 + 1));
                }
              }
            } else if (cmd == "LOAD") {
              cmdLoad(rest);
            } else if (cmd == "ADD_TX") {
              int c2 = rest.indexOf(',');
              int c3 = rest.indexOf(',', c2 + 1);
              int c4 = rest.indexOf(',', c3 + 1);
              if (c2 >= 0 && c3 >= 0 && c4 >= 0) {
                cmdAddTx(rest.substring(0, c2), rest.substring(c2 + 1, c3),
                         rest.substring(c3 + 1, c4), rest.substring(c4 + 1));
              } else {
                Serial.println("ERR,ADD_TX needs address,status,amount,timestamp");
              }
            } else if (cmd == "LIST_TX") {
              cmdListTx();
            } else {
              Serial.println("ERR,unknown command");
            }
          }
        }
        line = "";
      }
    } else {
      line += c;
    }
  }
  delay(10);
}

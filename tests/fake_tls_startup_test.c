#include "common/sha256.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-ext-server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail (const char *msg) {
  fprintf (stderr, "fake_tls_startup_test: %s\n", msg);
  exit (1);
}

static int read_u16 (const unsigned char *data, int pos) {
  return (data[pos] << 8) | data[pos + 1];
}

static void build_client_hello (unsigned char *client_hello, int len) {
  int i;
  memset (client_hello, 0, (size_t) len);
  client_hello[43] = 0x20;
  for (i = 0; i < 32; i++) {
    client_hello[44 + i] = (unsigned char) (0x40 + i);
  }
}

static void check_server_random_hmac (const unsigned char *response, int response_len,
                                      const unsigned char *client_random, const unsigned char *secret) {
  unsigned char *tmp = malloc ((size_t) response_len + 32);
  unsigned char digest[32];
  if (tmp == NULL) {
    fail ("OOM in HMAC check");
  }
  memcpy (tmp, client_random, 32);
  memcpy (tmp + 32, response, (size_t) response_len);
  memset (tmp + 32 + 11, 0, 32);
  if (sha256_hmac ((unsigned char *) secret, 16, tmp, response_len + 32, digest) < 0) {
    free (tmp);
    fail ("sha256_hmac failed in test");
  }
  if (memcmp (digest, response + 11, 32) != 0) {
    free (tmp);
    fail ("server_random HMAC mismatch");
  }
  free (tmp);
}

static void check_td_like (const unsigned char *response, int response_len,
                           const unsigned char *client_hello, const unsigned char *client_random,
                           const unsigned char *secret) {
  int pos = 0;
  if (response_len < 16) {
    fail ("TD: response too short");
  }
  if (memcmp (response, "\x16\x03\x03", 3) != 0) {
    fail ("TD: bad initial TLS record header");
  }
  pos += 3;
  {
    int server_hello_length = read_u16 (response, pos);
    pos += 2;
    if (server_hello_length <= 75 || server_hello_length + 5 >= response_len) {
      fail ("TD: invalid ServerHello length");
    }
    if (memcmp (response + 5, "\x02\x00", 2) != 0) {
      fail ("TD: bad ServerHello prefix");
    }
    if (memcmp (response + 9, "\x03\x03", 2) != 0) {
      fail ("TD: bad ServerHello version");
    }
    if (response[43] != 0x20) {
      fail ("TD: bad session_id length");
    }
    if (memcmp (response + 44, client_hello + 44, 32) != 0) {
      fail ("TD: session_id not mirrored");
    }
    if (response[76] != 0x13 || response[77] < 0x01 || response[77] > 0x03 || response[78] != 0x00) {
      fail ("TD: bad selected cipher/compression");
    }
    pos = 79;
    if (read_u16 (response, pos) + 76 != server_hello_length) {
      fail ("TD: bad extensions length");
    }
    pos += 2;
    {
      int sum = 0;
      while (pos < 5 + server_hello_length) {
        int ext = read_u16 (response, pos);
        int ext_len;
        pos += 2;
        if (ext != 0x33 && ext != 0x2b) {
          fail ("TD: unexpected ServerHello extension");
        }
        sum += ext;
        ext_len = read_u16 (response, pos);
        pos += 2;
        pos += ext_len;
      }
      if (sum != (0x33 + 0x2b)) {
        fail ("TD: missing or duplicated extensions");
      }
    }
  }
  if (memcmp (response + pos, "\x14\x03\x03\x00\x01\x01", 6) != 0) {
    fail ("TD: missing dummy CCS");
  }
  pos += 6;
  if (memcmp (response + pos, "\x17\x03\x03", 3) != 0) {
    fail ("TD: missing startup appdata record");
  }
  pos += 3;
  pos += 2 + read_u16 (response, pos);
  if (pos != response_len) {
    fail ("TD: extra startup TLS records");
  }
  check_server_random_hmac (response, response_len, client_random, secret);
}

static void check_ios_like (const unsigned char *response, int response_len,
                            const unsigned char *client_random, const unsigned char *secret) {
  int hello_len;
  if (response_len < 16 || memcmp (response, "\x16\x03\x03", 3) != 0) {
    fail ("iOS: bad hello header");
  }
  hello_len = read_u16 (response, 3);
  if (hello_len < 0 || hello_len > 10 * 1024 || response_len != 5 + hello_len + 9 + 2 + read_u16 (response, 5 + hello_len + 9)) {
    fail ("iOS: inconsistent lengths");
  }
  if (memcmp (response + 5 + hello_len, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
    fail ("iOS: bad startup tail marker");
  }
  check_server_random_hmac (response, response_len, client_random, secret);
}

static void check_desktop_like (const unsigned char *response, int response_len,
                                const unsigned char *client_random, const unsigned char *secret) {
  int hello_len;
  if (response_len < 16 || memcmp (response, "\x16\x03\x03", 3) != 0) {
    fail ("Desktop: bad hello header");
  }
  hello_len = read_u16 (response, 3);
  if (memcmp (response + 5 + hello_len, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
    fail ("Desktop: bad startup tail marker");
  }
  check_server_random_hmac (response, response_len, client_random, secret);
}

static void check_android_like (const unsigned char *response, int response_len,
                                const unsigned char *client_random, const unsigned char *secret) {
  int len1, len2;
  if (response_len < 16 || memcmp (response, "\x16\x03\x03", 3) != 0) {
    fail ("Android: bad first header");
  }
  len1 = read_u16 (response, 3);
  if (len1 > 64 * 1024 - 5) {
    fail ("Android: len1 too large");
  }
  if (memcmp (response + 5 + len1, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
    fail ("Android: bad hello2 marker");
  }
  len2 = read_u16 (response, 5 + len1 + 9);
  if (len2 > 64 * 1024 - len1 - 16) {
    fail ("Android: len2 too large");
  }
  if (response_len != 5 + len1 + 11 + len2) {
    fail ("Android: bad total startup length");
  }
  check_server_random_hmac (response, response_len, client_random, secret);
}

static void extract_template (const unsigned char *response, int response_len,
                              unsigned char **template_out, int *template_len_out, int *keyshare_offset_out) {
  int sh_len;
  int tpl_len;
  int i;
  static const unsigned char ks_hdr[] = {0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};

  if (response_len < 64 || memcmp (response, "\x16\x03\x03", 3) != 0) {
    fail ("extract_template: bad response");
  }
  sh_len = read_u16 (response, 3);
  tpl_len = 5 + sh_len;
  *template_out = malloc ((size_t) tpl_len);
  if (*template_out == NULL) {
    fail ("extract_template: OOM");
  }
  memcpy (*template_out, response, (size_t) tpl_len);
  *template_len_out = tpl_len;
  *keyshare_offset_out = -1;
  for (i = 0; i + (int) sizeof (ks_hdr) + 32 <= tpl_len; i++) {
    if (!memcmp (*template_out + i, ks_hdr, sizeof (ks_hdr))) {
      *keyshare_offset_out = i + (int) sizeof (ks_hdr);
      break;
    }
  }
}

static void run_case (int use_synth) {
  unsigned char client_hello[128];
  unsigned char client_random[32];
  unsigned char secret[16];
  unsigned char *response;
  unsigned char *template_data = NULL;
  int template_len = 0;
  int keyshare_offset = -1;
  int response_len = 0;
  struct tcp_rpc_tls_startup_meta meta;
  int i;

  build_client_hello (client_hello, (int) sizeof (client_hello));
  for (i = 0; i < 32; i++) {
    client_random[i] = (unsigned char) (0x90 + i);
  }
  for (i = 0; i < 16; i++) {
    secret[i] = (unsigned char) (0x11 + i);
  }

  response = tcp_rpc_build_tls_startup_response (
    client_hello,
    (int) sizeof (client_hello),
    client_random,
    secret,
    NULL,
    0,
    -1,
    1,
    0,
    0x01,
    2048,
    &response_len,
    &meta
  );
  if (response == NULL) {
    fail ("failed to build synthetic startup response");
  }

  if (!use_synth) {
    extract_template (response, response_len, &template_data, &template_len, &keyshare_offset);
    free (response);
    response = tcp_rpc_build_tls_startup_response (
      client_hello,
      (int) sizeof (client_hello),
      client_random,
      secret,
      template_data,
      template_len,
      keyshare_offset,
      0,
      0,
      0x02,
      2048,
      &response_len,
      &meta
    );
    if (response == NULL) {
      fail ("failed to build template startup response");
    }
  }

  if (meta.startup_appdata_records != 1) {
    fail ("meta: wrong startup appdata count");
  }
  if (meta.startup_shaping_plan_len != 0) {
    fail ("meta: startup shaping plan should be disabled");
  }

  check_td_like (response, response_len, client_hello, client_random, secret);
  check_ios_like (response, response_len, client_random, secret);
  check_desktop_like (response, response_len, client_random, secret);
  check_android_like (response, response_len, client_random, secret);

  free (response);
  free (template_data);
}

static int td_like_accepts (const unsigned char *response, int response_len,
                            const unsigned char *client_hello,
                            const unsigned char *client_random,
                            const unsigned char *secret) {
  int pos = 0;
  int server_hello_length;
  int appdata_len;
  unsigned char *tmp;
  unsigned char digest[32];

  if (response_len < 16 || memcmp (response, "\x16\x03\x03", 3) != 0) {
    return 0;
  }
  server_hello_length = read_u16 (response, 3);
  if (server_hello_length <= 75 || response_len < 5 + server_hello_length + 11) {
    return 0;
  }
  if (memcmp (response + 5, "\x02\x00", 2) != 0 || memcmp (response + 9, "\x03\x03", 2) != 0) {
    return 0;
  }
  if (response[43] != 0x20 || memcmp (response + 44, client_hello + 44, 32) != 0) {
    return 0;
  }
  pos = 79;
  if (read_u16 (response, pos) + 76 != server_hello_length) {
    return 0;
  }
  pos += 2;
  while (pos < 5 + server_hello_length) {
    int ext = read_u16 (response, pos);
    int ext_len;
    if (ext != 0x33 && ext != 0x2b) {
      return 0;
    }
    pos += 2;
    ext_len = read_u16 (response, pos);
    pos += 2 + ext_len;
    if (pos > 5 + server_hello_length) {
      return 0;
    }
  }
  if (pos != 5 + server_hello_length) {
    return 0;
  }
  if (memcmp (response + pos, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
    return 0;
  }
  pos += 9;
  appdata_len = read_u16 (response, pos);
  pos += 2 + appdata_len;
  if (pos != response_len) {
    return 0;
  }

  tmp = malloc ((size_t) response_len + 32);
  if (tmp == NULL) {
    return 0;
  }
  memcpy (tmp, client_random, 32);
  memcpy (tmp + 32, response, (size_t) response_len);
  memset (tmp + 32 + 11, 0, 32);
  if (sha256_hmac ((unsigned char *) secret, 16, tmp, response_len + 32, digest) < 0 ||
      memcmp (digest, response + 11, 32) != 0) {
    free (tmp);
    return 0;
  }
  free (tmp);
  return 1;
}

static void run_negative_cases (void) {
  unsigned char client_hello[128];
  unsigned char client_random[32];
  unsigned char secret[16];
  unsigned char *response;
  int response_len = 0;
  int i;

  build_client_hello (client_hello, (int) sizeof (client_hello));
  for (i = 0; i < 32; i++) {
    client_random[i] = (unsigned char) (0x90 + i);
  }
  for (i = 0; i < 16; i++) {
    secret[i] = (unsigned char) (0x11 + i);
  }

  response = tcp_rpc_build_tls_startup_response (
    client_hello,
    (int) sizeof (client_hello),
    client_random,
    secret,
    NULL,
    0,
    -1,
    1,
    0,
    0x01,
    1024,
    &response_len,
    NULL
  );
  if (response == NULL) {
    fail ("negative: failed to build baseline response");
  }

  {
    unsigned char *broken = malloc ((size_t) response_len + 16);
    int extra_pos;
    if (broken == NULL) {
      fail ("negative: OOM");
    }
    memcpy (broken, response, (size_t) response_len);
    extra_pos = response_len;
    memcpy (broken + extra_pos, "\x17\x03\x03\x00\x04\xaa\xbb\xcc\xdd", 9);
    if (td_like_accepts (broken, response_len + 9, client_hello, client_random, secret)) {
      fail ("negative: extra startup ApplicationData record accepted");
    }
    free (broken);
  }

  {
    unsigned char *broken = malloc ((size_t) response_len);
    if (broken == NULL) {
      fail ("negative: OOM");
    }
    memcpy (broken, response, (size_t) response_len);
    broken[5 + read_u16 (broken, 3)] ^= 1;
    if (td_like_accepts (broken, response_len, client_hello, client_random, secret)) {
      fail ("negative: broken dummy CCS accepted");
    }
    free (broken);
  }

  {
    unsigned char *broken = malloc ((size_t) response_len);
    if (broken == NULL) {
      fail ("negative: OOM");
    }
    memcpy (broken, response, (size_t) response_len);
    broken[11] ^= 1;
    if (td_like_accepts (broken, response_len, client_hello, client_random, secret)) {
      fail ("negative: broken server_random accepted");
    }
    free (broken);
  }

  free (response);
}

int main (void) {
  run_case (1);
  run_case (0);
  run_negative_cases ();
  puts ("fake_tls_startup_test: ok");
  return 0;
}

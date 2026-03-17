/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2018 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman
                    2016-2018 Nikolai Durov
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include <netdb.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "common/common-stats.h"
#include "common/kprintf.h"
#include "common/precise-time.h"
#include "common/resolver.h"
#include "common/rpc-const.h"
#include "common/sha256.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-events.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-thread.h"

#include "vv/vv-io.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
 *
 *                EXTERNAL RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_compact_parse_execute (connection_job_t c);
int tcp_rpcs_ext_alarm (connection_job_t c);
int tcp_rpcs_ext_init_accepted (connection_job_t c);
int tcp_rpcs_ext_close_connection (connection_job_t C, int who);

extern int tcp_rpcs_close_connection (connection_job_t C, int who);

conn_type_t ct_tcp_rpc_ext_server = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server",
  .init_accepted = tcp_rpcs_ext_init_accepted,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_ext_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_ext_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

int tcp_proxy_pass_parse_execute (connection_job_t C);
int tcp_proxy_pass_close (connection_job_t C, int who);
int tcp_proxy_pass_connected (connection_job_t C);
int tcp_proxy_pass_write_packet (connection_job_t c, struct raw_message *raw); 

conn_type_t ct_proxy_pass = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "proxypass",
  .init_accepted = server_failed,
  .parse_execute = tcp_proxy_pass_parse_execute,
  .connected = tcp_proxy_pass_connected,
  .close = tcp_proxy_pass_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
};

int tcp_proxy_pass_connected (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "proxy pass connected #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  return 0;
}

int tcp_proxy_pass_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    fail_connection (C, -1);
    return 0;
  }
  job_t E = job_incref (c->extra);
  struct connection_info *e = CONN_INFO(E);

  struct raw_message *r = rwm_alloc_raw_message ();
  rwm_move (r, &c->in);
  rwm_init (&c->in, 0);
  vkprintf (3, "proxying %d bytes to %s:%d\n", r->total_bytes, show_remote_ip (E), e->remote_port);
  mpq_push_w (e->out_queue, PTR_MOVE(r), 0);
  job_signal (JOB_REF_PASS (E), JS_RUN);
  return 0;
}

int tcp_proxy_pass_close (connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "closing proxy pass connection #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  if (c->extra) {
    job_t E = PTR_MOVE (c->extra);
    fail_connection (E, -23);
    job_decref (JOB_REF_PASS (E));
  }
  return cpu_server_close_connection (C, who);
}

int tcp_proxy_pass_write_packet (connection_job_t C, struct raw_message *raw) {
  rwm_union (&CONN_INFO(C)->out, raw);
  return 0;
}

int tcp_rpcs_default_execute (connection_job_t c, int op, struct raw_message *msg);

static unsigned char ext_secret[EXT_SECRET_MAX][16];
static int ext_secret_cnt = 0;

int tcp_rpcs_set_ext_secret (unsigned char secret[16]) {
  int i;
  for (i = 0; i < ext_secret_cnt; i++) {
    if (!memcmp (ext_secret[i], secret, 16)) {
      return 1;
    }
  }
  if (ext_secret_cnt >= EXT_SECRET_MAX) {
    return -1;
  }
  memcpy (ext_secret[ext_secret_cnt ++], secret, 16);
  return 0;
}

static int allow_only_tls;

static int fallback_backend_enabled;
static int fallback_relay_enabled;
static struct in_addr fallback_backend_target;
static unsigned char fallback_backend_target_ipv6[16];
static int fallback_backend_is_ipv6;
static int fallback_backend_port;
static char fallback_backend_printable[256];
static int max_secret_unique_ips;
static int max_secret_connections;
static unsigned long long max_secret_total_octets;
static int client_handshake_timeout = 3;
static int replay_cache_max_entries = 200000;
static int replay_cache_max_age = 2 * 86400;
static unsigned long long replay_cache_max_bytes;

// Aggregate throttling stats (no per-IP data, safe for /stats).
static unsigned long long probe_stat_calls;
static unsigned long long probe_stat_blocked;
static unsigned long long probe_stat_delayed;
static unsigned long long probe_stat_delay_ms_sum;
static unsigned long long dos_stat_undetermined_conns_closed;
static unsigned long long dos_stat_undetermined_bytes_closed;
static unsigned long long dos_stat_undetermined_global_conns_closed;
static unsigned long long dos_stat_undetermined_global_bytes_closed;
static unsigned long long dos_stat_undetermined_per_ip_conns_closed;
static unsigned long long tls_handshake_success;
static unsigned long long tls_handshake_fail_hmac;
static unsigned long long tls_handshake_fail_timestamp;
static unsigned long long tls_handshake_fail_replay;
static unsigned long long tls_handshake_timeouts;
static unsigned long long tls_delayed_reject_alert;
static unsigned long long tls_delayed_reject_close;
static unsigned long long tls_reject_non_tls;
static unsigned long long tls_replay_cache_entries;
static unsigned long long tls_replay_cache_evictions;
static unsigned long long tls_replay_cache_checks;
static unsigned long long tls_replay_cache_hits;
static unsigned long long tls_replay_cache_additions;
static unsigned long long tls_probe_table_ip_used;
static unsigned long long tls_probe_table_net_used;
static unsigned long long tls_secret_unique_ip_rejects;
static unsigned long long tls_secret_conn_limit_rejects;
static unsigned long long tls_secret_total_octet_rejects;
static unsigned long long tls_ip_allowlist_denied;
static unsigned long long tls_ip_blocklist_denied;
static unsigned long long tls_ip_acl_refresh_success;
static unsigned long long tls_ip_acl_refresh_fail;
static __thread unsigned int secret_conn_count[EXT_SECRET_MAX];
static __thread unsigned long long secret_total_octets[EXT_SECRET_MAX];

static int is_forbidden_obf2_prefix (const unsigned char random_header[64]) {
  static const unsigned char forbidden_ascii[][4] = {
    {'G', 'E', 'T', ' '},
    {'P', 'O', 'S', 'T'},
    {'H', 'E', 'A', 'D'},
    {'O', 'P', 'T', 'I'}
  };

  if (!memcmp (random_header, "\0\0\0\0", 4) ||
      !memcmp (random_header + 4, "\0\0\0\0", 4) ||
      !memcmp (random_header, "\xdd\xdd\xdd\xdd", 4) ||
      !memcmp (random_header, "\xee\xee\xee\xee", 4) ||
      !memcmp (random_header, "\xef\xef\xef\xef", 4)) {
    return 1;
  }

  int i;
  for (i = 0; i < (int)(sizeof (forbidden_ascii) / sizeof (forbidden_ascii[0])); i++) {
    if (!memcmp (random_header, forbidden_ascii[i], 4)) {
      return 1;
    }
  }

  return 0;
}

typedef struct {
  uint32_t start;
  uint32_t end;
} ip4_range_t;

typedef struct {
  uint64_t start_hi;
  uint64_t start_lo;
  uint64_t end_hi;
  uint64_t end_lo;
} ip6_range_t;

typedef struct {
  ip4_range_t *v4;
  int v4_num;
  ip6_range_t *v6;
  int v6_num;
  unsigned long long parsed_lines;
  unsigned long long active_lines;
  int loaded_at;
} ip_acl_set_t;

typedef struct {
  char *path;
  ip_acl_set_t *set;
  long long mtime;
  long long size;
} ip_acl_source_t;

static pthread_rwlock_t ip_acl_lock = PTHREAD_RWLOCK_INITIALIZER;
static ip_acl_source_t ip_blocklist;
static ip_acl_source_t ip_allowlist;
static int ip_acl_refresh_interval = 300;
static int ip_acl_next_refresh_time;

static void ip_acl_free_set (ip_acl_set_t *set) {
  if (!set) {
    return;
  }
  free (set->v4);
  free (set->v6);
  free (set);
}

static int ip_acl_u128_cmp (uint64_t ah, uint64_t al, uint64_t bh, uint64_t bl) {
  if (ah < bh) {
    return -1;
  }
  if (ah > bh) {
    return 1;
  }
  if (al < bl) {
    return -1;
  }
  if (al > bl) {
    return 1;
  }
  return 0;
}

static int ip_acl_cmp_v4 (const void *A, const void *B) {
  const ip4_range_t *a = A;
  const ip4_range_t *b = B;
  if (a->start < b->start) {
    return -1;
  }
  if (a->start > b->start) {
    return 1;
  }
  if (a->end < b->end) {
    return -1;
  }
  if (a->end > b->end) {
    return 1;
  }
  return 0;
}

static int ip_acl_cmp_v6 (const void *A, const void *B) {
  const ip6_range_t *a = A;
  const ip6_range_t *b = B;
  int c = ip_acl_u128_cmp (a->start_hi, a->start_lo, b->start_hi, b->start_lo);
  if (c) {
    return c;
  }
  return ip_acl_u128_cmp (a->end_hi, a->end_lo, b->end_hi, b->end_lo);
}

static int ip_acl_append_v4 (ip_acl_set_t *set, uint32_t start, uint32_t end) {
  assert (start <= end);
  ip4_range_t *v4 = realloc (set->v4, (size_t)(set->v4_num + 1) * sizeof (*set->v4));
  if (!v4) {
    return -1;
  }
  set->v4 = v4;
  set->v4[set->v4_num].start = start;
  set->v4[set->v4_num].end = end;
  set->v4_num++;
  return 0;
}

static int ip_acl_append_v6 (ip_acl_set_t *set, uint64_t sh, uint64_t sl, uint64_t eh, uint64_t el) {
  assert (ip_acl_u128_cmp (sh, sl, eh, el) <= 0);
  ip6_range_t *v6 = realloc (set->v6, (size_t)(set->v6_num + 1) * sizeof (*set->v6));
  if (!v6) {
    return -1;
  }
  set->v6 = v6;
  set->v6[set->v6_num].start_hi = sh;
  set->v6[set->v6_num].start_lo = sl;
  set->v6[set->v6_num].end_hi = eh;
  set->v6[set->v6_num].end_lo = el;
  set->v6_num++;
  return 0;
}

static int ip_acl_merge_v4 (ip_acl_set_t *set) {
  if (set->v4_num <= 1) {
    return 0;
  }
  qsort (set->v4, (size_t)set->v4_num, sizeof (*set->v4), ip_acl_cmp_v4);
  int out = 0;
  int i;
  for (i = 1; i < set->v4_num; i++) {
    ip4_range_t *cur = &set->v4[out];
    ip4_range_t *next = &set->v4[i];
    if (next->start <= cur->end || (cur->end != 0xffffffffu && next->start == cur->end + 1)) {
      if (next->end > cur->end) {
        cur->end = next->end;
      }
      continue;
    }
    set->v4[++out] = *next;
  }
  set->v4_num = out + 1;
  return 0;
}

static int ip_acl_merge_v6 (ip_acl_set_t *set) {
  if (set->v6_num <= 1) {
    return 0;
  }
  qsort (set->v6, (size_t)set->v6_num, sizeof (*set->v6), ip_acl_cmp_v6);
  int out = 0;
  int i;
  for (i = 1; i < set->v6_num; i++) {
    ip6_range_t *cur = &set->v6[out];
    ip6_range_t *next = &set->v6[i];
    uint64_t limit_hi = cur->end_hi;
    uint64_t limit_lo = cur->end_lo;
    if (limit_lo == ~0ULL) {
      if (limit_hi != ~0ULL) {
        limit_hi++;
        limit_lo = 0;
      }
    } else {
      limit_lo++;
    }
    if (ip_acl_u128_cmp (next->start_hi, next->start_lo, limit_hi, limit_lo) <= 0) {
      if (ip_acl_u128_cmp (next->end_hi, next->end_lo, cur->end_hi, cur->end_lo) > 0) {
        cur->end_hi = next->end_hi;
        cur->end_lo = next->end_lo;
      }
      continue;
    }
    set->v6[++out] = *next;
  }
  set->v6_num = out + 1;
  return 0;
}

static char *ip_acl_trim (char *s) {
  while (*s && isspace ((unsigned char)*s)) {
    s++;
  }
  if (!*s) {
    return s;
  }
  char *e = s + strlen (s) - 1;
  while (e >= s && isspace ((unsigned char)*e)) {
    *e-- = 0;
  }
  return s;
}

static void ip_acl_parse_ipv6_to_u128 (const unsigned char ip[16], uint64_t *hi, uint64_t *lo) {
  *hi = ((uint64_t)ip[0] << 56) | ((uint64_t)ip[1] << 48) | ((uint64_t)ip[2] << 40) | ((uint64_t)ip[3] << 32) |
        ((uint64_t)ip[4] << 24) | ((uint64_t)ip[5] << 16) | ((uint64_t)ip[6] << 8) | (uint64_t)ip[7];
  *lo = ((uint64_t)ip[8] << 56) | ((uint64_t)ip[9] << 48) | ((uint64_t)ip[10] << 40) | ((uint64_t)ip[11] << 32) |
        ((uint64_t)ip[12] << 24) | ((uint64_t)ip[13] << 16) | ((uint64_t)ip[14] << 8) | (uint64_t)ip[15];
}

static int ip_acl_parse_token (ip_acl_set_t *set, const char *token) {
  char buf[256];
  if ((int)strlen (token) >= (int)sizeof (buf)) {
    return -1;
  }
  strcpy (buf, token);
  char *slash = strchr (buf, '/');
  int prefix = -1;
  if (slash) {
    *slash++ = 0;
    if (!*slash) {
      return -1;
    }
    char *end = 0;
    errno = 0;
    long x = strtol (slash, &end, 10);
    if (errno || !end || *end) {
      return -1;
    }
    prefix = (int)x;
  }

  struct in_addr ip4;
  if (inet_pton (AF_INET, buf, &ip4) == 1) {
    if (prefix < 0) {
      prefix = 32;
    }
    if (prefix < 0 || prefix > 32) {
      return -1;
    }
    uint32_t ip = ntohl (ip4.s_addr);
    uint32_t mask = prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
    uint32_t start = ip & mask;
    uint32_t end = start | (~mask);
    return ip_acl_append_v4 (set, start, end);
  }

  unsigned char ip6[16];
  if (inet_pton (AF_INET6, buf, ip6) == 1) {
    if (prefix < 0) {
      prefix = 128;
    }
    if (prefix < 0 || prefix > 128) {
      return -1;
    }
    uint64_t hi, lo;
    ip_acl_parse_ipv6_to_u128 (ip6, &hi, &lo);
    uint64_t mask_hi = 0;
    uint64_t mask_lo = 0;
    if (prefix == 0) {
      mask_hi = 0;
      mask_lo = 0;
    } else if (prefix < 64) {
      mask_hi = ~0ULL << (64 - prefix);
      mask_lo = 0;
    } else if (prefix == 64) {
      mask_hi = ~0ULL;
      mask_lo = 0;
    } else if (prefix < 128) {
      mask_hi = ~0ULL;
      mask_lo = ~0ULL << (128 - prefix);
    } else {
      mask_hi = ~0ULL;
      mask_lo = ~0ULL;
    }
    uint64_t sh = hi & mask_hi;
    uint64_t sl = lo & mask_lo;
    uint64_t eh = sh | (~mask_hi);
    uint64_t el = sl | (~mask_lo);
    return ip_acl_append_v6 (set, sh, sl, eh, el);
  }

  return -1;
}

static int ip_acl_load_file (const char *filename, ip_acl_set_t **out, long long *mtime, long long *size) {
  struct stat st;
  if (stat (filename, &st) < 0) {
    vkprintf (0, "ip-acl: cannot stat '%s': %m\n", filename);
    return -1;
  }
  if (!S_ISREG (st.st_mode)) {
    vkprintf (0, "ip-acl: '%s' is not a regular file\n", filename);
    return -1;
  }

  FILE *fp = fopen (filename, "r");
  if (!fp) {
    vkprintf (0, "ip-acl: cannot open '%s': %m\n", filename);
    return -1;
  }

  ip_acl_set_t *set = calloc (1, sizeof (*set));
  if (!set) {
    fclose (fp);
    return -1;
  }

  char *line = 0;
  size_t cap = 0;
  ssize_t r;
  int line_no = 0;
  int ok = 0;

  while ((r = getline (&line, &cap, fp)) >= 0) {
    (void)r;
    line_no++;
    set->parsed_lines++;

    char *hash = strchr (line, '#');
    if (hash) {
      *hash = 0;
    }
    char *s = ip_acl_trim (line);
    if (!*s) {
      continue;
    }
    char *end = s;
    while (*end && !isspace ((unsigned char)*end)) {
      end++;
    }
    if (*end) {
      *end = 0;
    }
    if (ip_acl_parse_token (set, s) < 0) {
      vkprintf (0, "ip-acl: bad entry in '%s' at line %d: '%s'\n", filename, line_no, s);
      goto fail;
    }
    set->active_lines++;
  }
  if (ferror (fp)) {
    vkprintf (0, "ip-acl: read error in '%s': %m\n", filename);
    goto fail;
  }

  if (ip_acl_merge_v4 (set) < 0 || ip_acl_merge_v6 (set) < 0) {
    goto fail;
  }
  set->loaded_at = now ? now : (int)time (0);
  *out = set;
  *mtime = (long long)st.st_mtime;
  *size = (long long)st.st_size;
  ok = 1;

fail:
  if (!ok) {
    ip_acl_free_set (set);
  }
  free (line);
  fclose (fp);
  return ok ? 0 : -1;
}

static int ip_acl_match_v4 (const ip_acl_set_t *set, uint32_t ip) {
  if (!set || set->v4_num <= 0) {
    return 0;
  }
  int l = 0;
  int r = set->v4_num;
  while (l < r) {
    int m = l + ((r - l) >> 1);
    if (set->v4[m].start <= ip) {
      l = m + 1;
    } else {
      r = m;
    }
  }
  if (l <= 0) {
    return 0;
  }
  const ip4_range_t *x = &set->v4[l - 1];
  return x->end >= ip;
}

static int ip_acl_match_v6 (const ip_acl_set_t *set, const unsigned char ip[16]) {
  if (!set || set->v6_num <= 0) {
    return 0;
  }
  uint64_t hi, lo;
  ip_acl_parse_ipv6_to_u128 (ip, &hi, &lo);
  int l = 0;
  int r = set->v6_num;
  while (l < r) {
    int m = l + ((r - l) >> 1);
    if (ip_acl_u128_cmp (set->v6[m].start_hi, set->v6[m].start_lo, hi, lo) <= 0) {
      l = m + 1;
    } else {
      r = m;
    }
  }
  if (l <= 0) {
    return 0;
  }
  const ip6_range_t *x = &set->v6[l - 1];
  return ip_acl_u128_cmp (x->end_hi, x->end_lo, hi, lo) >= 0;
}

static int ip_acl_match_conn (const ip_acl_set_t *set, connection_job_t C) {
  const struct connection_info *c = CONN_INFO (C);
  if (c->flags & C_IPV6) {
    return ip_acl_match_v6 (set, c->remote_ipv6);
  }
  return ip_acl_match_v4 (set, c->remote_ip);
}

static int ip_acl_reload_source (ip_acl_source_t *src, int force) {
  if (!src->path || !*src->path) {
    return 0;
  }
  if (!force && src->set) {
    struct stat st;
    if (stat (src->path, &st) == 0 &&
        (long long)st.st_mtime == src->mtime &&
        (long long)st.st_size == src->size) {
      return 0;
    }
  }

  ip_acl_set_t *set = 0;
  long long mtime = 0;
  long long size = 0;
  if (ip_acl_load_file (src->path, &set, &mtime, &size) < 0) {
    return -1;
  }

  ip_acl_set_t *old = src->set;
  src->set = set;
  src->mtime = mtime;
  src->size = size;
  ip_acl_free_set (old);
  return 1;
}

static int ip_acl_reload_all (int force) {
  int refreshed = 0;
  pthread_rwlock_wrlock (&ip_acl_lock);
  int r1 = ip_acl_reload_source (&ip_allowlist, force);
  int r2 = ip_acl_reload_source (&ip_blocklist, force);
  if (r1 < 0 || r2 < 0) {
    refreshed = -1;
  } else if (r1 > 0 || r2 > 0) {
    refreshed = 1;
  }
  pthread_rwlock_unlock (&ip_acl_lock);
  return refreshed;
}

#ifndef MT_TLS_PROBE_TABLE_BITS
#define MT_TLS_PROBE_TABLE_BITS 13
#endif
#if MT_TLS_PROBE_TABLE_BITS < 8 || MT_TLS_PROBE_TABLE_BITS > 20
#error "MT_TLS_PROBE_TABLE_BITS must be in range [8, 20]"
#endif
#define PROBE_TABLE_SIZE (1u << MT_TLS_PROBE_TABLE_BITS)

static void probe_stat_note (int blocked, int delay_ms) {
  __atomic_fetch_add (&probe_stat_calls, 1, __ATOMIC_RELAXED);
  if (blocked) {
    __atomic_fetch_add (&probe_stat_blocked, 1, __ATOMIC_RELAXED);
    return;
  }
  if (delay_ms > 0) {
    __atomic_fetch_add (&probe_stat_delayed, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add (&probe_stat_delay_ms_sum, (unsigned long long)delay_ms, __ATOMIC_RELAXED);
  }
}

// Limit concurrent "undetermined" connections (D->in_packet_num == -3) per worker thread.
// This reduces idle socket pressure from connections that do not complete transport selection.
static int max_undetermined_conns = 1024;
static __thread int undetermined_conn_count;
static volatile int undetermined_conn_count_global;

// Process-wide cap for undetermined connections.
static int max_undetermined_conns_global = 8192;

// Upper bound on buffered bytes while the connection is still undetermined.
// If a peer sends a lot of junk before we can classify the transport, close early.
static int max_undetermined_buffer_bytes = 8192;
static volatile long long undetermined_bytes_global;

// Process-wide cap for bytes buffered in undetermined connections.
static long long max_undetermined_bytes_global = (64 << 20);
static int max_undetermined_conns_per_ip = 128;

#define UNDETERMINED_IP_TABLE_SIZE (1u << 12)
struct undetermined_ip_entry {
  unsigned ip4;
  unsigned char ip6[16];
  unsigned short refs;
  unsigned char is_ipv6;
  unsigned char state; // 0 = empty, 1 = used, 2 = tombstone
};
static __thread struct undetermined_ip_entry undetermined_ip_table[UNDETERMINED_IP_TABLE_SIZE];

// D->extra_int bit used by this file to track whether the connection is counted above.
#define EXT_TCPRPC_F_UNDET_COUNTED 1
#define EXT_TCPRPC_F_SECRET_CONN_COUNTED 2
#define EXT_TCPRPC_F_SECRET_QUOTA_HIT 4
#define EXT_TCPRPC_F_UNDET_IP_COUNTED 8

static unsigned undetermined_ip_hash4 (unsigned ip4) {
  return (ip4 * 2654435761u) & (UNDETERMINED_IP_TABLE_SIZE - 1);
}

static unsigned undetermined_ip_hash6 (const unsigned char ip6[16]) {
  unsigned w[4];
  memcpy (w, ip6, 16);
  unsigned h = w[0] ^ w[1] ^ w[2] ^ w[3];
  return (h * 2654435761u) & (UNDETERMINED_IP_TABLE_SIZE - 1);
}

static int undetermined_ip_entry_match (const struct undetermined_ip_entry *e, unsigned ip4, const unsigned char ip6[16], int is_ipv6) {
  if (e->state != 1 || e->is_ipv6 != (unsigned char)is_ipv6) {
    return 0;
  }
  if (!is_ipv6) {
    return e->ip4 == ip4;
  }
  return !memcmp (e->ip6, ip6, 16);
}

static int undetermined_conn_ip_enter (connection_job_t C) {
  if (max_undetermined_conns_per_ip <= 0) {
    return 0;
  }
  struct connection_info *c = CONN_INFO (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->extra_int & EXT_TCPRPC_F_UNDET_IP_COUNTED) {
    return 0;
  }

  int is_ipv6 = c->remote_ip ? 0 : 1;
  unsigned ip4 = c->remote_ip;
  unsigned char ip6[16];
  if (is_ipv6) {
    memcpy (ip6, c->remote_ipv6, 16);
  } else {
    memset (ip6, 0, 16);
  }
  unsigned idx = !is_ipv6 ? undetermined_ip_hash4 (ip4) : undetermined_ip_hash6 (ip6);
  int tomb = -1;
  int i;
  for (i = 0; i < (int)UNDETERMINED_IP_TABLE_SIZE; i++) {
    struct undetermined_ip_entry *e = &undetermined_ip_table[(idx + i) & (UNDETERMINED_IP_TABLE_SIZE - 1)];
    if (e->state == 0) {
      if (tomb >= 0) {
        e = &undetermined_ip_table[tomb];
      }
      e->state = 1;
      e->is_ipv6 = (unsigned char)is_ipv6;
      e->ip4 = ip4;
      memcpy (e->ip6, ip6, 16);
      e->refs = 1;
      D->extra_int |= EXT_TCPRPC_F_UNDET_IP_COUNTED;
      return 0;
    }
    if (e->state == 2) {
      if (tomb < 0) {
        tomb = (idx + i) & (UNDETERMINED_IP_TABLE_SIZE - 1);
      }
      continue;
    }
    if (undetermined_ip_entry_match (e, ip4, ip6, is_ipv6)) {
      if (e->refs >= max_undetermined_conns_per_ip) {
        return -1;
      }
      e->refs++;
      D->extra_int |= EXT_TCPRPC_F_UNDET_IP_COUNTED;
      return 0;
    }
  }
  if (tomb >= 0) {
    struct undetermined_ip_entry *e = &undetermined_ip_table[tomb];
    e->state = 1;
    e->is_ipv6 = (unsigned char)is_ipv6;
    e->ip4 = ip4;
    memcpy (e->ip6, ip6, 16);
    e->refs = 1;
    D->extra_int |= EXT_TCPRPC_F_UNDET_IP_COUNTED;
    return 0;
  }
  return -1;
}

static void undetermined_conn_ip_leave (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (!(D->extra_int & EXT_TCPRPC_F_UNDET_IP_COUNTED)) {
    return;
  }

  int is_ipv6 = c->remote_ip ? 0 : 1;
  unsigned ip4 = c->remote_ip;
  unsigned char ip6[16];
  if (is_ipv6) {
    memcpy (ip6, c->remote_ipv6, 16);
  } else {
    memset (ip6, 0, 16);
  }
  unsigned idx = !is_ipv6 ? undetermined_ip_hash4 (ip4) : undetermined_ip_hash6 (ip6);
  int i;
  for (i = 0; i < (int)UNDETERMINED_IP_TABLE_SIZE; i++) {
    struct undetermined_ip_entry *e = &undetermined_ip_table[(idx + i) & (UNDETERMINED_IP_TABLE_SIZE - 1)];
    if (e->state == 0) {
      break;
    }
    if (!undetermined_ip_entry_match (e, ip4, ip6, is_ipv6)) {
      continue;
    }
    if (e->refs > 1) {
      e->refs--;
    } else {
      e->refs = 0;
      e->state = 2;
    }
    break;
  }
  D->extra_int &= ~EXT_TCPRPC_F_UNDET_IP_COUNTED;
}

static void undetermined_conn_account_bytes (connection_job_t C, int cur_bytes) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (!(D->extra_int & EXT_TCPRPC_F_UNDET_COUNTED)) {
    return;
  }
  if (cur_bytes < 0) {
    cur_bytes = 0;
  }
  int prev = D->extra_int4;
  if (cur_bytes > prev) {
    __atomic_fetch_add (&undetermined_bytes_global, (long long)(cur_bytes - prev), __ATOMIC_RELAXED);
  } else if (cur_bytes < prev) {
    __atomic_fetch_sub (&undetermined_bytes_global, (long long)(prev - cur_bytes), __ATOMIC_RELAXED);
  }
  D->extra_int4 = cur_bytes;
}

static int undetermined_conn_enter (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->in_packet_num != -3 || (D->extra_int & EXT_TCPRPC_F_UNDET_COUNTED)) {
    return 0;
  }
  if (undetermined_conn_ip_enter (C) < 0) {
    return -1;
  }
  D->extra_int |= EXT_TCPRPC_F_UNDET_COUNTED;
  undetermined_conn_count++;
  __atomic_fetch_add (&undetermined_conn_count_global, 1, __ATOMIC_RELAXED);
  D->extra_int4 = c->in.total_bytes > 0 ? c->in.total_bytes : 0;
  if (D->extra_int4 > 0) {
    __atomic_fetch_add (&undetermined_bytes_global, (long long) D->extra_int4, __ATOMIC_RELAXED);
  }
  return 0;
}

static void undetermined_conn_leave (connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if ((D->extra_int & EXT_TCPRPC_F_UNDET_COUNTED)) {
    if (D->extra_int4 > 0) {
      __atomic_fetch_sub (&undetermined_bytes_global, (long long) D->extra_int4, __ATOMIC_RELAXED);
      D->extra_int4 = 0;
    }
    D->extra_int &= ~EXT_TCPRPC_F_UNDET_COUNTED;
    if (undetermined_conn_count > 0) {
      undetermined_conn_count--;
    }
    __atomic_fetch_sub (&undetermined_conn_count_global, 1, __ATOMIC_RELAXED);
  }
  undetermined_conn_ip_leave (C);
}

#define DOMAIN_PROFILE_MAX 8
#define DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX 4
#define MAX_PROBE_SERVER_HELLO_PAYLOAD 8192
#define MAX_PROBE_ENCRYPTED_RECORD_PAYLOAD 16384
#define MAX_SERVER_HELLO_TEMPLATE_LEN 2048

struct domain_profile {
  short encrypted_size[3];
  char encrypted_records; // 1..3
  char is_reversed_extension_order;
  unsigned short weight;  // number of matching probe samples
  unsigned char *server_hello_template;
  int server_hello_template_len;
  int server_hello_keyshare_offset;
  short startup_payload_families[DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX];
  unsigned short startup_payload_family_weights[DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX];
  unsigned char startup_payload_families_num;
};

struct domain_info {
  const char *domain;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  short server_hello_encrypted_size2;
  short server_hello_encrypted_size3;
  char use_random_encrypted_size;
  char use_random_encrypted_size2;
  char use_random_encrypted_size3;
  char is_reversed_extension_order;
  char server_hello_encrypted_records;  // number of encrypted appdata records to send (1..3)
  // Captured from upstream response during startup probing and reused as template.
  // This is only the first TLS Handshake record:
  // [0..template_len) == "\x16\x03\x03" + uint16(record_len) + ServerHello payload.
  unsigned char *server_hello_template;
  int server_hello_template_len;
  int server_hello_keyshare_offset; // where 32-byte keyshare starts inside template, or -1
  struct domain_profile profiles[DOMAIN_PROFILE_MAX];
  int profiles_num;
  struct domain_info *next;
};

static struct domain_info *default_domain_info;

#define DOMAIN_HASH_MOD 257
static struct domain_info *domains[DOMAIN_HASH_MOD];

static struct domain_info **get_domain_info_bucket (const char *domain, size_t len) {
  size_t i;
  unsigned hash = 0;
  for (i = 0; i < len; i++) {
    hash = hash * 239017 + (unsigned char)domain[i];
  }
  return domains + hash % DOMAIN_HASH_MOD;
}

static const struct domain_info *get_domain_info (const char *domain, size_t len) {
  struct domain_info *info = *get_domain_info_bucket (domain, len);
  while (info != NULL) {
    if (strlen (info->domain) == len && memcmp (domain, info->domain, len) == 0) {
      return info;
    }
    info = info->next;
  }
  return NULL;
}

static void free_domain_profiles (struct domain_info *info) {
  int i;
  for (i = 0; i < info->profiles_num; i++) {
    free (info->profiles[i].server_hello_template);
    info->profiles[i].server_hello_template = NULL;
    info->profiles[i].server_hello_template_len = 0;
    info->profiles[i].server_hello_keyshare_offset = -1;
    info->profiles[i].weight = 0;
    info->profiles[i].startup_payload_families_num = 0;
  }
  info->profiles_num = 0;
}

static const struct domain_profile *choose_domain_profile (const struct domain_info *info) {
  if (info == NULL || info->profiles_num <= 0) {
    return NULL;
  }

  int total = 0;
  int i;
  for (i = 0; i < info->profiles_num; i++) {
    int w = info->profiles[i].weight > 0 ? info->profiles[i].weight : 1;
    total += w;
  }
  if (total <= 0) {
    return &info->profiles[0];
  }

  unsigned int r = (unsigned int) lrand48_j ();
  int pick = (int)(r % (unsigned int)total);
  for (i = 0; i < info->profiles_num; i++) {
    int w = info->profiles[i].weight > 0 ? info->profiles[i].weight : 1;
    if (pick < w) {
      return &info->profiles[i];
    }
    pick -= w;
  }
  return &info->profiles[info->profiles_num - 1];
}

static int get_domain_server_hello_encrypted_size (const struct domain_info *info) {
  if (info->use_random_encrypted_size) {
    unsigned int r = (unsigned int) lrand48_j ();
    return info->server_hello_encrypted_size + ((r >> 1) & 1) - (r & 1);
  } else {
    return info->server_hello_encrypted_size;
  }
}

static int get_domain_server_hello_encrypted_records (const struct domain_info *info) {
  int n = info->server_hello_encrypted_records;
  return (n >= 1 && n <= 3) ? n : 1;
}

static int get_domain_server_hello_encrypted_size_n (const struct domain_info *info, int idx) {
  switch (idx) {
  case 0:
    return get_domain_server_hello_encrypted_size (info);
  case 1:
    if (info->use_random_encrypted_size2) {
      unsigned int r = (unsigned int) lrand48_j ();
      return info->server_hello_encrypted_size2 + ((r >> 1) & 1) - (r & 1);
    }
    return info->server_hello_encrypted_size2;
  case 2:
    if (info->use_random_encrypted_size3) {
      unsigned int r = (unsigned int) lrand48_j ();
      return info->server_hello_encrypted_size3 + ((r >> 1) & 1) - (r & 1);
    }
    return info->server_hello_encrypted_size3;
  default:
    return 0;
  }
}

static int get_profile_server_hello_encrypted_records (const struct domain_info *info, const struct domain_profile *profile) {
  if (profile != NULL) {
    int n = profile->encrypted_records;
    return (n >= 1 && n <= 3) ? n : 1;
  }
  return get_domain_server_hello_encrypted_records (info);
}

static int get_profile_server_hello_encrypted_size_n (const struct domain_info *info, const struct domain_profile *profile, int idx) {
  if (profile != NULL) {
    if (idx < 0 || idx > 2) {
      return 0;
    }
    return profile->encrypted_size[idx];
  }
  return get_domain_server_hello_encrypted_size_n (info, idx);
}

static int jitter_profile_encrypted_size (const struct domain_info *info, const struct domain_profile *profile, int idx, int base) {
  if (base <= 1 || idx < 0 || idx > 2) {
    return base;
  }

  int minv = base;
  int maxv = base;
  if (info && info->profiles_num > 1) {
    int i;
    for (i = 0; i < info->profiles_num; i++) {
      const struct domain_profile *p = &info->profiles[i];
      if (p == profile) {
        continue;
      }
      if (p->encrypted_records <= idx) {
        continue;
      }
      int v = p->encrypted_size[idx];
      if (v <= 0) {
        continue;
      }
      if (v < minv) { minv = v; }
      if (v > maxv) { maxv = v; }
    }
  }

  int spread = maxv - minv;
  int rel = base >> 6; // ~1.5% of baseline
  int max_delta = spread / 2;
  if (rel > max_delta) {
    max_delta = rel;
  }
  if (max_delta > 96) {
    max_delta = 96;
  }
  if (max_delta > base - 1) {
    max_delta = base - 1;
  }
  if (max_delta <= 0) {
    return base;
  }

  unsigned int r = (unsigned int) lrand48_j ();
  int delta = (int)(r % (unsigned int)(2 * max_delta + 1)) - max_delta;
  int out = base + delta;
  if (out < 1) {
    out = 1;
  }
  return out;
}

static int choose_tls_startup_payload_size (int base_payload_size) {
  enum {
    TLS_STARTUP_SIZE_JITTER_MIN = 50,
    TLS_STARTUP_SIZE_JITTER_MAX = 500
  };
  int families[3];
  int families_n = 0;
  int size;
  int room;
  unsigned int jr;
  int size_jitter;

  if (base_payload_size < 1) {
    base_payload_size = 1;
  } else if (base_payload_size > 16384) {
    base_payload_size = 16384;
  }

  families[families_n++] = base_payload_size;
  if (base_payload_size <= 16000) {
    int step1 = base_payload_size + ((base_payload_size >= 4096) ? 96 : 64);
    if (step1 > 16384) {
      step1 = 16384;
    }
    if (step1 > base_payload_size) {
      families[families_n++] = step1;
    }
  }
  if (base_payload_size <= 15872) {
    int step2 = base_payload_size + ((base_payload_size >= 4096) ? 224 : 160);
    if (step2 > 16384) {
      step2 = 16384;
    }
    if (step2 > families[families_n - 1]) {
      families[families_n++] = step2;
    }
  }

  size = families[(unsigned int) lrand48_j () % (unsigned int) families_n];
  if (size < 16384) {
    jr = (unsigned int) lrand48_j ();
    if ((jr & 7) != 0) {
      room = 16384 - size;
      size_jitter = TLS_STARTUP_SIZE_JITTER_MIN + (int)(jr % (TLS_STARTUP_SIZE_JITTER_MAX - TLS_STARTUP_SIZE_JITTER_MIN + 1));
      if (size_jitter > room) {
        size_jitter = room;
      }
      if (size_jitter > 0) {
        size += size_jitter;
      }
    }
  }
  return size;
}

int tcp_rpc_collapse_startup_payload_size (int encrypted_records, const int *encrypted_sizes) {
  int i;
  int encrypted_wire_total = 0;

  if (encrypted_records < 1) {
    encrypted_records = 1;
  } else if (encrypted_records > 3) {
    encrypted_records = 3;
  }

  for (i = 0; i < encrypted_records; i++) {
    int sz = encrypted_sizes[i];
    if (sz <= 0) {
      sz = 1;
    }
    encrypted_wire_total += 5 + sz;
  }

  if (encrypted_wire_total <= 5) {
    return 1;
  }
  return encrypted_wire_total - 5;
}

static void domain_profile_note_startup_payload_family (struct domain_profile *profile, int payload_size) {
  int i;
  int best_idx = -1;
  int best_dist = 0x7fffffff;
  int weakest_idx = -1;
  unsigned short weakest_weight = 0xffff;

  if (profile == NULL) {
    return;
  }

  if (payload_size < 1) {
    payload_size = 1;
  } else if (payload_size > 16384) {
    payload_size = 16384;
  }

  for (i = 0; i < profile->startup_payload_families_num; i++) {
    int dist = abs ((int) profile->startup_payload_families[i] - payload_size);
    if (dist == 0) {
      if (profile->startup_payload_family_weights[i] < 65535) {
        profile->startup_payload_family_weights[i]++;
      }
      return;
    }
    if (dist <= 96 && dist < best_dist) {
      best_dist = dist;
      best_idx = i;
    }
    if (profile->startup_payload_family_weights[i] < weakest_weight) {
      weakest_weight = profile->startup_payload_family_weights[i];
      weakest_idx = i;
    }
  }

  if (best_idx >= 0) {
    short cur = profile->startup_payload_families[best_idx];
    unsigned short weight = profile->startup_payload_family_weights[best_idx];
    int blended = ((int) cur * (int) weight + payload_size) / ((int) weight + 1);
    profile->startup_payload_families[best_idx] = (short) blended;
    if (profile->startup_payload_family_weights[best_idx] < 65535) {
      profile->startup_payload_family_weights[best_idx]++;
    }
    return;
  }

  if (profile->startup_payload_families_num < DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX) {
    i = profile->startup_payload_families_num++;
    profile->startup_payload_families[i] = (short) payload_size;
    profile->startup_payload_family_weights[i] = 1;
    return;
  }

  if (weakest_idx >= 0 && weakest_weight <= 1) {
    profile->startup_payload_families[weakest_idx] = (short) payload_size;
    profile->startup_payload_family_weights[weakest_idx] = 1;
  }
}

int tcp_rpc_choose_startup_payload_size_from_families (
  const short *families,
  const unsigned short *weights,
  int families_num,
  int fallback_base
) {
  int i;
  int total = 0;
  int pick;
  int base;
  int minv = 0;
  int maxv = 0;
  int max_delta;
  unsigned int r;
  int delta;

  if (families == NULL || weights == NULL || families_num <= 0) {
    return choose_tls_startup_payload_size (fallback_base);
  }
  if (families_num > DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX) {
    families_num = DOMAIN_PROFILE_PAYLOAD_FAMILY_MAX;
  }

  for (i = 0; i < families_num; i++) {
    int w = weights[i] > 0 ? weights[i] : 1;
    total += w;
  }
  if (total <= 0) {
    return choose_tls_startup_payload_size (fallback_base);
  }

  pick = (int)((unsigned int) lrand48_j () % (unsigned int) total);
  base = families[0];
  for (i = 0; i < families_num; i++) {
    int w = weights[i] > 0 ? weights[i] : 1;
    if (pick < w) {
      base = families[i];
      break;
    }
    pick -= w;
  }

  if (base < 1) {
    base = 1;
  } else if (base > 16384) {
    base = 16384;
  }

  minv = maxv = base;
  for (i = 0; i < families_num; i++) {
    int v = families[i];
    if (v <= 0) {
      continue;
    }
    if (v < minv) { minv = v; }
    if (v > maxv) { maxv = v; }
  }

  max_delta = (maxv - minv) / 2;
  if ((base >> 7) > max_delta) {
    max_delta = base >> 7;
  }
  if (max_delta < 16) {
    max_delta = 16;
  }
  if (max_delta > 64) {
    max_delta = 64;
  }
  if (max_delta > base - 1) {
    max_delta = base - 1;
  }
  if (max_delta <= 0) {
    return base;
  }

  r = (unsigned int) lrand48_j ();
  delta = (int)(r % (unsigned int)(2 * max_delta + 1)) - max_delta;
  base += delta;
  if (base < 1) {
    base = 1;
  } else if (base > 16384) {
    base = 16384;
  }
  return base;
}

int tcp_rpc_proxy_domains_prepare_stat (stats_buffer_t *sb) {
  sb_printf (sb, ">>>>>>tls_transport>>>>>>\tstart\n");
  sb_printf (sb, "tls_transport_only\t%d\n", allow_only_tls ? 1 : 0);

  sb_printf (sb, "tls_default_domain\t%s\n",
             (default_domain_info && default_domain_info->domain) ? "[redacted]" : "-");

  sb_printf (sb, "tls_fallback_backend_enabled\t%d\n", fallback_backend_enabled ? 1 : 0);
  sb_printf (sb, "tls_fallback_relay_enabled\t%d\n", fallback_relay_enabled ? 1 : 0);
  if (fallback_backend_enabled) {
    sb_printf (sb, "tls_fallback_backend\t%s\n", fallback_backend_printable[0] ? "[redacted]" : "-");
    sb_printf (sb, "tls_fallback_backend_is_ipv6\t%d\n", fallback_backend_is_ipv6 ? 1 : 0);
    sb_printf (sb, "tls_fallback_backend_port\t%d\n", fallback_backend_port);
  }

  char allow_path[256] = "-";
  char block_path[256] = "-";
  int allow_v4 = 0, allow_v6 = 0, allow_loaded = 0;
  int block_v4 = 0, block_v6 = 0, block_loaded = 0;
  pthread_rwlock_rdlock (&ip_acl_lock);
  if (ip_allowlist.path && *ip_allowlist.path) {
    snprintf (allow_path, sizeof (allow_path), "%s", ip_allowlist.path);
  }
  if (ip_blocklist.path && *ip_blocklist.path) {
    snprintf (block_path, sizeof (block_path), "%s", ip_blocklist.path);
  }
  if (ip_allowlist.set) {
    allow_v4 = ip_allowlist.set->v4_num;
    allow_v6 = ip_allowlist.set->v6_num;
    allow_loaded = ip_allowlist.set->loaded_at;
  }
  if (ip_blocklist.set) {
    block_v4 = ip_blocklist.set->v4_num;
    block_v6 = ip_blocklist.set->v6_num;
    block_loaded = ip_blocklist.set->loaded_at;
  }
  pthread_rwlock_unlock (&ip_acl_lock);

  sb_printf (sb, "tls_ip_acl_refresh_interval_sec\t%d\n", ip_acl_refresh_interval);
  sb_printf (sb, "tls_ip_allowlist_file\t%s\n", strcmp (allow_path, "-") ? "[configured]" : "-");
  sb_printf (sb, "tls_ip_allowlist_loaded_at\t%d\n", allow_loaded);
  sb_printf (sb, "tls_ip_allowlist_ranges_v4\t%d\n", allow_v4);
  sb_printf (sb, "tls_ip_allowlist_ranges_v6\t%d\n", allow_v6);
  sb_printf (sb, "tls_ip_blocklist_file\t%s\n", strcmp (block_path, "-") ? "[configured]" : "-");
  sb_printf (sb, "tls_ip_blocklist_loaded_at\t%d\n", block_loaded);
  sb_printf (sb, "tls_ip_blocklist_ranges_v4\t%d\n", block_v4);
  sb_printf (sb, "tls_ip_blocklist_ranges_v6\t%d\n", block_v6);
  sb_printf (sb, "tls_ip_allowlist_denied\t%llu\n", __atomic_load_n (&tls_ip_allowlist_denied, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_ip_blocklist_denied\t%llu\n", __atomic_load_n (&tls_ip_blocklist_denied, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_ip_acl_refresh_success\t%llu\n", __atomic_load_n (&tls_ip_acl_refresh_success, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_ip_acl_refresh_fail\t%llu\n", __atomic_load_n (&tls_ip_acl_refresh_fail, __ATOMIC_RELAXED));

  sb_printf (sb, "tls_probe_throttle_calls\t%llu\n", __atomic_load_n (&probe_stat_calls, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_probe_throttle_blocked\t%llu\n", __atomic_load_n (&probe_stat_blocked, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_probe_throttle_delayed\t%llu\n", __atomic_load_n (&probe_stat_delayed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_probe_throttle_delay_ms_sum\t%llu\n", __atomic_load_n (&probe_stat_delay_ms_sum, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_probe_table_size\t%u\n", (unsigned)PROBE_TABLE_SIZE);
  sb_printf (sb, "tls_probe_table_bits\t%d\n", (int)MT_TLS_PROBE_TABLE_BITS);
  sb_printf (sb, "tls_probe_table_ip_used\t%llu\n", __atomic_load_n (&tls_probe_table_ip_used, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_probe_table_net_used\t%llu\n", __atomic_load_n (&tls_probe_table_net_used, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_replay_cache_entries\t%llu\n", __atomic_load_n (&tls_replay_cache_entries, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_replay_cache_evictions\t%llu\n", __atomic_load_n (&tls_replay_cache_evictions, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_replay_cache_max_entries\t%d\n", replay_cache_max_entries);
  sb_printf (sb, "tls_replay_cache_max_age_sec\t%d\n", replay_cache_max_age);
  sb_printf (sb, "tls_replay_cache_max_bytes\t%llu\n", replay_cache_max_bytes);
  unsigned long long replay_checks = __atomic_load_n (&tls_replay_cache_checks, __ATOMIC_RELAXED);
  unsigned long long replay_hits = __atomic_load_n (&tls_replay_cache_hits, __ATOMIC_RELAXED);
  sb_printf (sb, "tls_replay_cache_checks\t%llu\n", replay_checks);
  sb_printf (sb, "tls_replay_cache_hits\t%llu\n", replay_hits);
  sb_printf (sb, "tls_replay_cache_additions\t%llu\n", __atomic_load_n (&tls_replay_cache_additions, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_replay_cache_hit_rate_ppm\t%llu\n", replay_checks ? (replay_hits * 1000000ULL) / replay_checks : 0ULL);
  unsigned long long secret_active_connections = 0;
  unsigned long long secret_total_octets_sum = 0;
  int si;
  for (si = 0; si < ext_secret_cnt && si < EXT_SECRET_MAX; si++) {
    secret_active_connections += (unsigned long long) secret_conn_count[si];
    secret_total_octets_sum += secret_total_octets[si];
  }
  sb_printf (sb, "tls_secret_unique_ip_limit\t%d\n", max_secret_unique_ips);
  sb_printf (sb, "tls_secret_unique_ip_rejects\t%llu\n", __atomic_load_n (&tls_secret_unique_ip_rejects, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_secret_conn_limit\t%d\n", max_secret_connections);
  sb_printf (sb, "tls_secret_conn_rejects\t%llu\n", __atomic_load_n (&tls_secret_conn_limit_rejects, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_secret_active_connections\t%llu\n", secret_active_connections);
  sb_printf (sb, "tls_secret_total_octet_quota\t%llu\n", max_secret_total_octets);
  sb_printf (sb, "tls_secret_total_octet_rejects\t%llu\n", __atomic_load_n (&tls_secret_total_octet_rejects, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_secret_total_octets\t%llu\n", secret_total_octets_sum);
  sb_printf (sb, "tls_dos_undetermined_conns_limit\t%d\n", max_undetermined_conns);
  sb_printf (sb, "tls_dos_undetermined_conns_global_limit\t%d\n", max_undetermined_conns_global);
  sb_printf (sb, "tls_dos_undetermined_conns_per_ip_limit\t%d\n", max_undetermined_conns_per_ip);
  sb_printf (sb, "tls_dos_undetermined_conns_global_now\t%d\n", (int)__atomic_load_n (&undetermined_conn_count_global, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_bytes_limit\t%d\n", max_undetermined_buffer_bytes);
  sb_printf (sb, "tls_dos_undetermined_bytes_global_limit\t%lld\n", max_undetermined_bytes_global);
  sb_printf (sb, "tls_dos_undetermined_bytes_global_now\t%lld\n", (long long)__atomic_load_n (&undetermined_bytes_global, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_conns_closed\t%llu\n", __atomic_load_n (&dos_stat_undetermined_conns_closed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_global_conns_closed\t%llu\n", __atomic_load_n (&dos_stat_undetermined_global_conns_closed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_per_ip_conns_closed\t%llu\n", __atomic_load_n (&dos_stat_undetermined_per_ip_conns_closed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_bytes_closed\t%llu\n", __atomic_load_n (&dos_stat_undetermined_bytes_closed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_dos_undetermined_global_bytes_closed\t%llu\n", __atomic_load_n (&dos_stat_undetermined_global_bytes_closed, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_handshake_success\t%llu\n", __atomic_load_n (&tls_handshake_success, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_handshake_fail_hmac\t%llu\n", __atomic_load_n (&tls_handshake_fail_hmac, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_handshake_fail_timestamp\t%llu\n", __atomic_load_n (&tls_handshake_fail_timestamp, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_handshake_fail_replay\t%llu\n", __atomic_load_n (&tls_handshake_fail_replay, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_handshake_timeouts\t%llu\n", __atomic_load_n (&tls_handshake_timeouts, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_client_handshake_timeout_sec\t%d\n", client_handshake_timeout);
  sb_printf (sb, "tls_delayed_reject_alert\t%llu\n", __atomic_load_n (&tls_delayed_reject_alert, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_delayed_reject_close\t%llu\n", __atomic_load_n (&tls_delayed_reject_close, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_reject_non_tls\t%llu\n", __atomic_load_n (&tls_reject_non_tls, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_bulk_small_record_delays\t%llu\n", __atomic_load_n (&tls_bulk_small_record_delays, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_bulk_small_record_flushes\t%llu\n", __atomic_load_n (&tls_bulk_small_record_flushes, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_long_flow_phase_transitions\t%llu\n", __atomic_load_n (&tls_long_flow_phase_transitions, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_long_flow_bulk_bytes_shaped\t%llu\n", __atomic_load_n (&tls_long_flow_bulk_bytes_shaped, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_encrypt_len_overrun_events\t%llu\n", __atomic_load_n (&tls_encrypt_len_overrun_events, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_encrypt_short_encrypt_events\t%llu\n", __atomic_load_n (&tls_encrypt_short_encrypt_events, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_encrypt_short_encrypt_requested_bytes\t%llu\n", __atomic_load_n (&tls_encrypt_short_encrypt_requested_bytes, __ATOMIC_RELAXED));
  sb_printf (sb, "tls_encrypt_short_encrypt_available_bytes\t%llu\n", __atomic_load_n (&tls_encrypt_short_encrypt_available_bytes, __ATOMIC_RELAXED));

  int idx = 0;
  int i;
  for (i = 0; i < DOMAIN_HASH_MOD; i++) {
    struct domain_info *info = domains[i];
    while (info != NULL) {
      const char *d = info->domain ? info->domain : "-";
      sb_printf (sb, "tls_domain_%d\t%s\n", idx, d);
      sb_printf (sb, "tls_domain_%d_profiles\t%d\n", idx, info->profiles_num);
      sb_printf (sb, "tls_domain_%d_is_reversed_extension_order\t%d\n", idx, (int)info->is_reversed_extension_order);
      sb_printf (sb, "tls_domain_%d_records\t%d\n", idx, (int)get_domain_server_hello_encrypted_records (info));

      sb_printf (sb, "tls_domain_%d_size0\t%d\n", idx, (int)info->server_hello_encrypted_size);
      sb_printf (sb, "tls_domain_%d_size1\t%d\n", idx, (int)info->server_hello_encrypted_size2);
      sb_printf (sb, "tls_domain_%d_size2\t%d\n", idx, (int)info->server_hello_encrypted_size3);

      sb_printf (sb, "tls_domain_%d_use_random0\t%d\n", idx, (int)info->use_random_encrypted_size);
      sb_printf (sb, "tls_domain_%d_use_random1\t%d\n", idx, (int)info->use_random_encrypted_size2);
      sb_printf (sb, "tls_domain_%d_use_random2\t%d\n", idx, (int)info->use_random_encrypted_size3);

      sb_printf (sb, "tls_domain_%d_server_hello_template_len\t%d\n", idx, (int)info->server_hello_template_len);
      sb_printf (sb, "tls_domain_%d_server_hello_keyshare_offset\t%d\n", idx, (int)info->server_hello_keyshare_offset);

      idx++;
      info = info->next;
    }
  }

  sb_printf (sb, "tls_domains_count\t%d\n", idx);
  sb_printf (sb, "<<<<<<tls_transport<<<<<<\tend\n");
  return sb->pos;
}

#define TLS_REQUEST_LENGTH 517
#define MAX_TLS_RESPONSE_ALLOC (1 << 15)

static BIGNUM *get_y2 (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns y^2 = x^3 + 486662 * x^2 + x
  BIGNUM *y = BN_dup (x);
  assert (y != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 486662) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  BN_clear_free (coef);
  return y;
}

static BIGNUM *get_double_x (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns x_2 = (x^2 - 1)^2/(4*y^2)
  BIGNUM *denominator = get_y2 (x, mod, big_num_context);
  assert (denominator != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 4) == 1);
  assert (BN_mod_mul (denominator, denominator, coef, mod, big_num_context) == 1);

  BIGNUM *numerator = BN_new();
  assert (numerator != NULL);
  assert (BN_mod_mul (numerator, x, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_sub (numerator, numerator, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (numerator, numerator, numerator, mod, big_num_context) == 1);

  assert (BN_mod_inverse (denominator, denominator, mod, big_num_context) == denominator);
  assert (BN_mod_mul (numerator, numerator, denominator, mod, big_num_context) == 1);

  BN_clear_free (coef);
  BN_clear_free (denominator);
  return numerator;
}

static int generate_public_key_slow_bn (unsigned char key[32]) {
  BIGNUM *mod = NULL;
  assert (BN_hex2bn (&mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") == 64);
  BIGNUM *pow = NULL;
  assert (BN_hex2bn (&pow, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6") == 64);
  BN_CTX *big_num_context = BN_CTX_new();
  assert (big_num_context != NULL);

  BIGNUM *x = BN_new();
  while (1) {
    if (RAND_bytes (key, 32) != 1) {
      BN_clear_free (x);
      BN_CTX_free (big_num_context);
      BN_clear_free (pow);
      BN_clear_free (mod);
      return 0;
    }
    key[31] &= 127;
    BN_bin2bn (key, 32, x);
    assert (x != NULL);
    assert (BN_mod_mul (x, x, x, mod, big_num_context) == 1);

    BIGNUM *y = get_y2 (x, mod, big_num_context);

    BIGNUM *r = BN_new();
    assert (BN_mod_exp (r, y, pow, mod, big_num_context) == 1);
    BN_clear_free (y);
    if (BN_is_one (r)) {
      BN_clear_free (r);
      break;
    }
    BN_clear_free (r);
  }

  int i;
  for (i = 0; i < 3; i++) {
    BIGNUM *x2 = get_double_x (x, mod, big_num_context);
    BN_clear_free (x);
    x = x2;
  }

  int num_size = BN_num_bytes (x);
  assert (num_size <= 32);
  memset (key, '\0', 32 - num_size);
  assert (BN_bn2bin (x, key + (32 - num_size)) == num_size);
  for (i = 0; i < 16; i++) {
    unsigned char t = key[i];
    key[i] = key[31 - i];
    key[31 - i] = t;
  }

  BN_clear_free (x);
  BN_CTX_free (big_num_context);
  BN_clear_free (pow);
  BN_clear_free (mod);
  return 1;
}

static int generate_public_key (unsigned char key[32]) {
  // Generate an X25519 public key for the ServerHello key_share extension.
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_X25519, NULL);
  EVP_PKEY *pkey = NULL;
  size_t len = 32;

  if (pctx &&
      EVP_PKEY_keygen_init (pctx) > 0 &&
      EVP_PKEY_keygen (pctx, &pkey) > 0 &&
      EVP_PKEY_get_raw_public_key (pkey, key, &len) > 0 &&
      len == 32) {
    EVP_PKEY_free (pkey);
    EVP_PKEY_CTX_free (pctx);
    return 1;
  }

  EVP_PKEY_free (pkey);
  EVP_PKEY_CTX_free (pctx);

  // Fallback for unusual OpenSSL builds.
  return generate_public_key_slow_bn (key);
}

static int generate_probe_public_key_p521 (unsigned char key[133]) {
  int ok = 0;
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_secp521r1);
  if (ec == NULL) {
    return 0;
  }
  if (EC_KEY_generate_key (ec) != 1) {
    EC_KEY_free (ec);
    return 0;
  }
  const EC_GROUP *group = EC_KEY_get0_group (ec);
  const EC_POINT *point = EC_KEY_get0_public_key (ec);
  if (group != NULL && point != NULL) {
    size_t len = EC_POINT_point2oct (group, point, POINT_CONVERSION_UNCOMPRESSED, key, 133, NULL);
    ok = (len == 133);
  }
  EC_KEY_free (ec);
  return ok;
}

unsigned char *tcp_rpc_build_tls_startup_response (
  const unsigned char *client_hello,
  int client_hello_len,
  const unsigned char *client_random,
  const unsigned char *secret,
  const unsigned char *selected_template,
  int selected_template_len,
  int selected_keyshare_offset,
  int use_synth,
  int effective_reversed_order,
  unsigned char cipher_suite_id,
  int encrypted_payload_size,
  int *out_len,
  struct tcp_rpc_tls_startup_meta *meta
) {
  if (out_len == NULL || client_hello == NULL || client_random == NULL || secret == NULL) {
    return NULL;
  }
  if (client_hello_len < 78 || encrypted_payload_size < 1 || encrypted_payload_size > 16384) {
    return NULL;
  }
  if (!use_synth && (selected_template == NULL || selected_template_len <= 0)) {
    return NULL;
  }

  const int server_hello_rec_len = use_synth ? 127 : selected_template_len;
  const int response_size = server_hello_rec_len + 6 + 5 + encrypted_payload_size;
  if (response_size <= 0 || response_size > MAX_TLS_RESPONSE_ALLOC - 32) {
    return NULL;
  }

  unsigned char *response = malloc ((size_t) response_size);
  if (response == NULL) {
    return NULL;
  }

  int pos = 0;
  if (!use_synth) {
    memcpy (response, selected_template, (size_t) selected_template_len);
    if (selected_template_len >= 11 + 32) {
      memset (response + 11, 0, 32);
    }
    if (selected_template_len >= 44 + 32) {
      response[43] = '\x20';
      memcpy (response + 44, client_hello + 44, 32);
    }
    if (selected_template_len >= 78) {
      response[76] = 0x13;
      response[77] = cipher_suite_id;
    }
    if (selected_keyshare_offset >= 0 &&
        selected_keyshare_offset + 32 <= selected_template_len &&
        !generate_public_key (response + selected_keyshare_offset)) {
      free (response);
      return NULL;
    }
    pos = selected_template_len;
  } else {
    memcpy (response, "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03", 11);
    memset (response + 11, 0, 32);
    response[43] = '\x20';
    memcpy (response + 44, client_hello + 44, 32);
    memcpy (response + 76, "\x13\x01\x00\x00\x2e", 5);
    response[77] = cipher_suite_id;

    pos = 81;
    {
      int tls_server_extensions[3] = {0x33, 0x2b, -1};
      if (effective_reversed_order) {
        int t = tls_server_extensions[0];
        tls_server_extensions[0] = tls_server_extensions[1];
        tls_server_extensions[1] = t;
      }
      int i;
      for (i = 0; tls_server_extensions[i] != -1; i++) {
        if (tls_server_extensions[i] == 0x33) {
          memcpy (response + pos, "\x00\x33\x00\x24\x00\x1d\x00\x20", 8);
          if (!generate_public_key (response + pos + 8)) {
            free (response);
            return NULL;
          }
          pos += 40;
        } else if (tls_server_extensions[i] == 0x2b) {
          memcpy (response + pos, "\x00\x2b\x00\x02\x03\x04", 6);
          pos += 6;
        }
      }
    }
    if (pos != 127) {
      free (response);
      return NULL;
    }
  }

  memcpy (response + pos, "\x14\x03\x03\x00\x01\x01", 6);
  pos += 6;
  memcpy (response + pos, "\x17\x03\x03", 3);
  pos += 3;
  response[pos++] = (unsigned char)(encrypted_payload_size >> 8);
  response[pos++] = (unsigned char)(encrypted_payload_size & 255);
  if (RAND_bytes (response + pos, encrypted_payload_size) != 1) {
    free (response);
    return NULL;
  }
  pos += encrypted_payload_size;

  if (pos != response_size) {
    free (response);
    return NULL;
  }

  unsigned char *hmac_input = malloc ((size_t) response_size + 32);
  if (hmac_input == NULL) {
    free (response);
    return NULL;
  }
  memcpy (hmac_input, client_random, 32);
  memcpy (hmac_input + 32, response, (size_t) response_size);

  unsigned char server_random[32];
  if (sha256_hmac ((unsigned char *)secret, 16, hmac_input, 32 + response_size, server_random) < 0) {
    free (hmac_input);
    free (response);
    return NULL;
  }
  memcpy (response + 11, server_random, 32);
  free (hmac_input);

  if (meta) {
    meta->encrypted_payload_size = encrypted_payload_size;
    meta->response_size = response_size;
    meta->startup_appdata_records = 1;
    meta->startup_shaping_plan_len = 0;
  }
  *out_len = response_size;
  return response;
}

static void add_string (unsigned char *str, int *pos, const char *data, int data_len) {
  assert (*pos + data_len <= TLS_REQUEST_LENGTH);
  memcpy (str + (*pos), data, data_len);
  (*pos) += data_len;
}

static int add_random (unsigned char *str, int *pos, int random_len) {
  assert (*pos + random_len <= TLS_REQUEST_LENGTH);
  if (RAND_bytes (str + (*pos), random_len) != 1) {
    return 0;
  }
  (*pos) += random_len;
  return 1;
}

static void add_length (unsigned char *str, int *pos, int length) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = (unsigned char)(length / 256);
  str[*pos + 1] = (unsigned char)(length % 256);
  (*pos) += 2;
}

static void add_grease (unsigned char *str, int *pos, const unsigned char *greases, int num) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = greases[num];
  str[*pos + 1] = greases[num];
  (*pos) += 2;
}

static int add_public_key (unsigned char *str, int *pos) {
  assert (*pos + 32 <= TLS_REQUEST_LENGTH);
  if (!generate_public_key (str + (*pos))) {
    return 0;
  }
  (*pos) += 32;
  return 1;
}

static int add_probe_keyshares (unsigned char *str, int *pos, const unsigned char *greases) {
  assert (*pos + 5 + 36 + 137 <= TLS_REQUEST_LENGTH);
  add_grease (str, pos, greases, 4);
  add_string (str, pos, "\x00\x01\x00\x00\x1d\x00\x20", 7);
  if (!add_public_key (str, pos)) {
    return 0;
  }
  add_string (str, pos, "\x00\x19\x00\x85", 4);
  if (!generate_probe_public_key_p521 (str + (*pos))) {
    return 0;
  }
  (*pos) += 133;
  return 1;
}

static unsigned char *create_request (const char *domain) {
  unsigned char *result = malloc (TLS_REQUEST_LENGTH);
  if (result == NULL) {
    return NULL;
  }
  int pos = 0;

#define MAX_GREASE 7
  unsigned char greases[MAX_GREASE];
  if (RAND_bytes (greases, MAX_GREASE) != 1) {
    free (result);
    return NULL;
  }
  int i;
  for (i = 0; i < MAX_GREASE; i++) {
    greases[i] = (unsigned char)((greases[i] & 0xF0) + 0x0A);
  }
  for (i = 1; i < MAX_GREASE; i += 2) {
    if (greases[i] == greases[i - 1]) {
      greases[i] = (unsigned char)(0x10 ^ greases[i]);
    }
  }
#undef MAX_GREASE

  int domain_length = (int)strlen (domain);

  add_string (result, &pos, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", 11);
  if (!add_random (result, &pos, 32)) {
    free (result);
    return NULL;
  }
  add_string (result, &pos, "\x20", 1);
  if (!add_random (result, &pos, 32)) {
    free (result);
    return NULL;
  }
  add_string (result, &pos, "\x00\x22", 2);
  add_grease (result, &pos, greases, 0);
  add_string (result, &pos, "\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
                            "\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91", 36);
  add_grease (result, &pos, greases, 2);
  add_string (result, &pos, "\x00\x00\x00\x00", 4);
  add_length (result, &pos, domain_length + 5);
  add_length (result, &pos, domain_length + 3);
  add_string (result, &pos, "\x00", 1);
  add_length (result, &pos, domain_length);
  add_string (result, &pos, domain, domain_length);
  add_string (result, &pos, "\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0c\x00\x0a", 15);
  add_grease (result, &pos, greases, 4);
  add_string (result, &pos, "\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10"
                            "\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05"
                            "\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04"
                            "\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00"
                            "\x33\x00\xb4\x00\xb2", 79);
  if (!add_probe_keyshares (result, &pos, greases)) {
    free (result);
    return NULL;
  }
  add_string (result, &pos, "\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a", 11);
  add_grease (result, &pos, greases, 6);
  add_string (result, &pos, "\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02", 15);
  add_grease (result, &pos, greases, 3);
  add_string (result, &pos, "\x00\x01\x00\x00\x15", 5);

  int padding_length = TLS_REQUEST_LENGTH - 2 - pos;
  assert (padding_length >= 0);
  add_length (result, &pos, padding_length);
  memset (result + pos, 0, TLS_REQUEST_LENGTH - pos);
  return result;
}

static int read_length (const unsigned char *response, int *pos) {
  *pos += 2;
  return response[*pos - 2] * 256 + response[*pos - 1];
}

static int check_response (const unsigned char *response, int len, const unsigned char *request_session_id,
                           int *is_reversed_extension_order,
                           int *encrypted_application_data_records,
                           int encrypted_application_data_lengths[3]) {
#define FAIL(error) {                                               \
    kprintf ("Failed to parse upstream TLS response: " error "\n"); \
    return 0;                                                       \
  }
#define CHECK_LENGTH(length)  \
  if (pos + (length) > len) { \
    FAIL("Too short");        \
  }
#define EXPECT_BYTES(offset, bytes, bytes_len, error)                                             \
  do {                                                                                             \
    if ((offset) < 0 || (bytes_len) < 0 || (offset) + (bytes_len) > len ||                       \
        memcmp (response + (offset), (bytes), (bytes_len)) != 0) {                                \
      FAIL(error);                                                                                 \
    }                                                                                              \
  } while (0)

  int pos = 0;
  static const unsigned char tls_record_header[] = {0x16, 0x03, 0x03};
  static const unsigned char server_hello_prefix[] = {0x02, 0x00};
  static const unsigned char tls13_version[] = {0x03, 0x03};
  static const unsigned char session_id_len_32[] = {0x20};
  static const unsigned char dummy_ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
  static const unsigned char appdata_prefix[] = {0x17, 0x03, 0x03};

  EXPECT_BYTES(0, tls_record_header, (int)sizeof (tls_record_header), "Non-TLS response or TLS <= 1.1");
  pos += 3;
  CHECK_LENGTH(2);
  int server_hello_length = read_length (response, &pos);
  if (server_hello_length <= 39) {
    FAIL("Receive too short ServerHello");
  }
  CHECK_LENGTH(server_hello_length);

  EXPECT_BYTES(5, server_hello_prefix, (int)sizeof (server_hello_prefix), "Non-TLS response 2");
  EXPECT_BYTES(9, tls13_version, (int)sizeof (tls13_version), "Non-TLS response 3");

  if (memcmp (response + 11, "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91"
                             "\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c", 32) == 0) {
    FAIL("TLS 1.3 servers returning HelloRetryRequest are not supprted");
  }
  if (response[43] == '\x00') {
    FAIL("TLS <= 1.2: empty session_id");
  }
  EXPECT_BYTES(43, session_id_len_32, (int)sizeof (session_id_len_32), "Non-TLS response 4");
  if (server_hello_length <= 75) {
    FAIL("Receive too short server hello 2");
  }
  if (memcmp (response + 44, request_session_id, 32) != 0) {
    FAIL("TLS <= 1.2: expected mirrored session_id");
  }
  // In TLS 1.3 the ServerHello selects a cipher suite (2 bytes) and a compression method (1 byte, must be 0).
  // Our synthetic ClientHello offers 0x1301..0x1303; different domains choose different ones.
  if (response[76] != 0x13 || response[77] < 0x01 || response[77] > 0x03 || response[78] != 0x00) {
    FAIL("TLS <= 1.2: can't recognize chosen cipher/compression");
  }
  pos += 74;
  int extensions_length = read_length (response, &pos);
  if (extensions_length + 76 != server_hello_length) {
    FAIL("Receive wrong extensions length");
  }
  int sum = 0;
  while (pos < 5 + server_hello_length - 4) {
    int extension_id = read_length (response, &pos);
    if (extension_id != 0x33 && extension_id != 0x2b) {
      FAIL("Receive unexpected extension");
    }
    if (pos == 83) {
      *is_reversed_extension_order = (extension_id == 0x2b);
    }
    sum += extension_id;

    int extension_length = read_length (response, &pos);
    if (pos + extension_length > 5 + server_hello_length) {
      FAIL("Receive wrong extension length");
    }
    if (extension_id == 0x33) {
      if (extension_length < 4) {
        FAIL("Unexpected key_share extension length");
      }
    } else if (extension_length != 2) {
      FAIL("Unexpected extension length");
    }
    pos += extension_length;
  }
  if (sum != 0x33 + 0x2b) {
    FAIL("Receive duplicate extensions");
  }
  if (pos != 5 + server_hello_length) {
    FAIL("Receive wrong extensions list");
  }

  CHECK_LENGTH(9);
  EXPECT_BYTES(pos, dummy_ccs, (int)sizeof (dummy_ccs), "Expected dummy ChangeCipherSpec");
  pos += 6;

  int rec_cnt = 0;
  while (pos < len) {
    CHECK_LENGTH(5);
    EXPECT_BYTES(pos, appdata_prefix, (int)sizeof (appdata_prefix), "Expected encrypted application data");
    pos += 3;

    CHECK_LENGTH(2);
    int rlen = read_length (response, &pos);
    if (rlen == 0) {
      FAIL("Receive empty encrypted application data");
    }
    CHECK_LENGTH(rlen);
    if (rec_cnt < 3) {
      encrypted_application_data_lengths[rec_cnt] = rlen;
    }
    rec_cnt++;
    pos += rlen;
  }

  if (pos != len) {
    FAIL("Too long");
  }
  *encrypted_application_data_records = rec_cnt;
#undef FAIL
#undef CHECK_LENGTH
#undef EXPECT_BYTES

  return 1;
}

static int extract_server_hello_template (const unsigned char *resp, int rlen,
                                          unsigned char **out_tpl, int *out_tpl_len, int *out_keyshare_offset) {
  if (resp == NULL || rlen < 64 || memcmp (resp, "\x16\x03\x03", 3) != 0) {
    return 0;
  }
  int sh_len = resp[3] * 256 + resp[4];
  int tpl_len = 5 + sh_len;
  if (sh_len <= 0 || tpl_len > rlen || tpl_len > MAX_SERVER_HELLO_TEMPLATE_LEN) {
    return 0;
  }

  unsigned char *tpl = malloc ((size_t)tpl_len);
  if (tpl == NULL) {
    return 0;
  }
  memcpy (tpl, resp, (size_t)tpl_len);

  int keyshare_off = -1;
  static const unsigned char ks_hdr[] = {0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
  int j;
  for (j = 0; j + (int)sizeof (ks_hdr) + 32 <= tpl_len; j++) {
    if (!memcmp (tpl + j, ks_hdr, sizeof (ks_hdr))) {
      keyshare_off = j + (int)sizeof (ks_hdr);
      break;
    }
  }

  *out_tpl = tpl;
  *out_tpl_len = tpl_len;
  *out_keyshare_offset = keyshare_off;
  return 1;
}

static void domain_profile_note_startup_payload_family (struct domain_profile *profile, int payload_size);
static void domain_profile_merge_startup_payload_families (struct domain_profile *dst, const struct domain_profile *src);

static int domain_profile_equals (const struct domain_profile *a, const struct domain_profile *b) {
  if (a->encrypted_records != b->encrypted_records ||
      a->is_reversed_extension_order != b->is_reversed_extension_order ||
      a->encrypted_size[0] != b->encrypted_size[0] ||
      a->encrypted_size[1] != b->encrypted_size[1] ||
      a->encrypted_size[2] != b->encrypted_size[2] ||
      a->server_hello_template_len != b->server_hello_template_len) {
    return 0;
  }
  if (a->server_hello_template_len <= 0) {
    return 1;
  }
  return !memcmp (a->server_hello_template, b->server_hello_template, (size_t)a->server_hello_template_len);
}

static void domain_profile_merge_startup_payload_families (struct domain_profile *dst, const struct domain_profile *src) {
  int i;
  if (dst == NULL || src == NULL) {
    return;
  }
  for (i = 0; i < src->startup_payload_families_num; i++) {
    int j;
    int reps = src->startup_payload_family_weights[i] > 0 ? src->startup_payload_family_weights[i] : 1;
    for (j = 0; j < reps; j++) {
      domain_profile_note_startup_payload_family (dst, src->startup_payload_families[i]);
    }
  }
}

static int update_domain_info (struct domain_info *info) {
  const char *domain = info->domain;
  struct hostent *host = kdb_gethostbyname (domain);
  if (host == NULL || host->h_addr == NULL) {
    kprintf ("Failed to resolve host %s\n", domain);
    return 0;
  }
  assert (host->h_addrtype == AF_INET || host->h_addrtype == AF_INET6);

  fd_set read_fd;
  fd_set write_fd;
  fd_set except_fd;
  FD_ZERO(&read_fd);
  FD_ZERO(&write_fd);
  FD_ZERO(&except_fd);

#define TRIES 20
#define MIN_PROBE_SUCCESSES 5
  int sockets[TRIES];
  unsigned char *requests[TRIES] = {};
  unsigned char *responses[TRIES] = {};
  int response_len[TRIES] = {};
  int is_encrypted_application_data_length_read[TRIES] = {};  // 0 = need first appdata length; 1 = have it
  int encrypted_application_data_records_read[TRIES] = {};    // number of complete appdata records read into buffer (max 3)
  int have_error = 0;
  int ok = 0;
  int i;
  int completed_count = 0;
  for (i = 0; i < TRIES; i++) {
    sockets[i] = -1;
  }
  int is_failed[TRIES] = {};
  for (i = 0; i < TRIES; i++) {
    sockets[i] = socket (host->h_addrtype, SOCK_STREAM, IPPROTO_TCP);
    if (sockets[i] < 0) {
      kprintf ("Failed to open socket for %s: %s\n", domain, strerror (errno));
      is_failed[i] = 1;
      completed_count++;
      continue;
    }
    if (fcntl (sockets[i], F_SETFL, O_NONBLOCK) == -1) {
      kprintf ("Failed to make socket non-blocking: %s\n", strerror (errno));
      close (sockets[i]);
      sockets[i] = -1;
      is_failed[i] = 1;
      completed_count++;
      continue;
    }

    int e_connect;
    if (host->h_addrtype == AF_INET) {
      info->target = *((struct in_addr *) host->h_addr);
      memset (info->target_ipv6, 0, sizeof (info->target_ipv6));

      struct sockaddr_in addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons (443);
      memcpy (&addr.sin_addr, host->h_addr, sizeof (struct in_addr));

      e_connect = connect (sockets[i], &addr, sizeof (addr));
    } else {
      assert (sizeof (struct in6_addr) == sizeof (info->target_ipv6));
      info->target.s_addr = 0;
      memcpy (info->target_ipv6, host->h_addr, sizeof (struct in6_addr));

      struct sockaddr_in6 addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons (443);
      memcpy (&addr.sin6_addr, host->h_addr, sizeof (struct in6_addr));

      e_connect = connect (sockets[i], &addr, sizeof (addr));
    }

    if (e_connect == -1 && errno != EINPROGRESS) {
      kprintf ("Failed to connect to %s: %s\n", domain, strerror (errno));
      close (sockets[i]);
      sockets[i] = -1;
      is_failed[i] = 1;
      completed_count++;
      continue;
    }
  }

  for (i = 0; i < TRIES; i++) {
    if (is_failed[i]) {
      continue;
    }
    requests[i] = create_request (domain);
    if (requests[i] == NULL) {
      kprintf ("Failed to build probe request for checking domain %s\n", domain);
      if (sockets[i] >= 0) {
        close (sockets[i]);
        sockets[i] = -1;
      }
      is_failed[i] = 1;
      completed_count++;
    }
  }

  int finished_count = 0;
  int is_written[TRIES] = {};
  int is_finished[TRIES] = {};
  int read_pos[TRIES] = {};
  double finish_time = get_utime_monotonic() + 5.0;
  int try_is_reversed_extension_order[TRIES] = {};
  int try_encrypted_application_data_records[TRIES] = {};
  int try_encrypted_application_data_lengths[TRIES][3] = {{0}};
  int is_reversed_extension_order_min = 0;
  int is_reversed_extension_order_max = 0;
  while (get_utime_monotonic() < finish_time && finished_count < MIN_PROBE_SUCCESSES &&
         completed_count < TRIES && !have_error) {
    struct timeval timeout_data;
    timeout_data.tv_sec = (int)(finish_time - precise_now + 1);
    timeout_data.tv_usec = 0;

    int max_fd = 0;
    for (i = 0; i < TRIES; i++) {
      if (is_finished[i] || is_failed[i]) {
        continue;
      }
      if (is_written[i]) {
        FD_SET(sockets[i], &read_fd);
        FD_CLR(sockets[i], &write_fd);
      } else {
        FD_CLR(sockets[i], &read_fd);
        FD_SET(sockets[i], &write_fd);
      }
      FD_SET(sockets[i], &except_fd);
      if (sockets[i] > max_fd) {
        max_fd = sockets[i];
      }
    }

    select (max_fd + 1, &read_fd, &write_fd, &except_fd, &timeout_data);

    for (i = 0; i < TRIES; i++) {
      if (is_finished[i] || is_failed[i]) {
        continue;
      }
      if (FD_ISSET(sockets[i], &read_fd)) {
        assert (is_written[i]);

        unsigned char header[5];
        if (responses[i] == NULL) {
          ssize_t read_res = read (sockets[i], header, sizeof (header));
          if (read_res != sizeof (header)) {
            kprintf ("Failed to read response header for checking domain %s: %s\n", domain, read_res == -1 ? strerror (errno) : "Read less bytes than expected");
            is_failed[i] = 1;
            completed_count++;
            continue;
          }
          if (memcmp (header, "\x16\x03\x03", 3) != 0) {
            kprintf ("Non-TLS response, or TLS <= 1.1, or unsuccessful request to %s: receive \\x%02x\\x%02x\\x%02x\\x%02x\\x%02x...\n",
                     domain, header[0], header[1], header[2], header[3], header[4]);
            is_failed[i] = 1;
            completed_count++;
            continue;
          }
          int sh_len = header[3] * 256 + header[4];
          if (sh_len <= 0 || sh_len > MAX_PROBE_SERVER_HELLO_PAYLOAD) {
            kprintf ("Unreasonable ServerHello record length from %s: %d\n", domain, sh_len);
            is_failed[i] = 1;
            completed_count++;
            continue;
          }
          response_len[i] = 5 + sh_len + 6 + 5;
          responses[i] = malloc (response_len[i]);
          if (responses[i] == NULL) {
            kprintf ("Failed to allocate %d bytes for domain probe response (%s)\n", response_len[i], domain);
            is_failed[i] = 1;
            completed_count++;
            continue;
          }
          memcpy (responses[i], header, sizeof (header));
          read_pos[i] = 5;
        } else {
          ssize_t read_res = read (sockets[i], responses[i] + read_pos[i], response_len[i] - read_pos[i]);
          if (read_res == -1) {
            kprintf ("Failed to read response from %s: %s\n", domain, strerror (errno));
            is_failed[i] = 1;
            completed_count++;
            continue;
          }
          read_pos[i] += read_res;

          if (read_pos[i] == response_len[i]) {
            if (!is_encrypted_application_data_length_read[i]) {
              if (memcmp (responses[i] + response_len[i] - 11, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
                kprintf ("Not found TLS 1.3 support on domain %s\n", domain);
                is_failed[i] = 1;
                completed_count++;
                continue;
              }

              is_encrypted_application_data_length_read[i] = 1;
              int encrypted_application_data_length = responses[i][response_len[i] - 2] * 256 + responses[i][response_len[i] - 1];
              if (encrypted_application_data_length <= 0 || encrypted_application_data_length > MAX_PROBE_ENCRYPTED_RECORD_PAYLOAD) {
                kprintf ("Unreasonable TLS ApplicationData record length from %s: %d\n", domain, encrypted_application_data_length);
                is_failed[i] = 1;
                completed_count++;
                continue;
              }
              response_len[i] += encrypted_application_data_length;
              unsigned char *new_buffer = realloc (responses[i], response_len[i]);
              if (new_buffer == NULL) {
                kprintf ("Failed to grow domain probe buffer to %d bytes (%s)\n", response_len[i], domain);
                is_failed[i] = 1;
                completed_count++;
                continue;
              }
              responses[i] = new_buffer;
              continue;
            }

            // Finished reading one full encrypted application data record.
            if (encrypted_application_data_records_read[i] < 3) {
              encrypted_application_data_records_read[i]++;
            }

            // Try to read additional encrypted appdata records if immediately available.
            if (encrypted_application_data_records_read[i] < 3) {
              unsigned char hdr2[5];
              ssize_t pr = recv (sockets[i], hdr2, 5, MSG_PEEK);
              if (pr == 5 && !memcmp (hdr2, "\x17\x03\x03", 3)) {
                int l2 = hdr2[3] * 256 + hdr2[4];
                if (l2 > 0 && l2 <= MAX_PROBE_ENCRYPTED_RECORD_PAYLOAD) {
                  response_len[i] += 5 + l2;
                  unsigned char *new_buffer = realloc (responses[i], response_len[i]);
                  if (new_buffer == NULL) {
                    kprintf ("Failed to grow domain probe buffer to %d bytes (%s)\n", response_len[i], domain);
                    is_failed[i] = 1;
                    completed_count++;
                    continue;
                  }
                  responses[i] = new_buffer;
                  continue;
                }
              }
            }

            int is_reversed_extension_order = -1;
            int encrypted_application_data_records = -1;
            int encrypted_application_data_lengths[3] = {0, 0, 0};
            if (check_response (responses[i], response_len[i], requests[i] + 44,
                                &is_reversed_extension_order,
                                &encrypted_application_data_records,
                                encrypted_application_data_lengths)) {
              assert (is_reversed_extension_order != -1);
              assert (encrypted_application_data_records > 0);
              try_is_reversed_extension_order[i] = is_reversed_extension_order;
              try_encrypted_application_data_records[i] = encrypted_application_data_records;
              {
                int k;
                for (k = 0; k < 3; k++) {
                  try_encrypted_application_data_lengths[i][k] = encrypted_application_data_lengths[k];
                }
              }

              FD_CLR(sockets[i], &write_fd);
              FD_CLR(sockets[i], &read_fd);
              FD_CLR(sockets[i], &except_fd);
              is_finished[i] = 1;
              finished_count++;
              completed_count++;
            } else {
              is_failed[i] = 1;
              completed_count++;
              continue;
            }
          }
        }
      }
      if (FD_ISSET(sockets[i], &write_fd)) {
        assert (!is_written[i]);
        ssize_t write_res = write (sockets[i], requests[i], TLS_REQUEST_LENGTH);
        if (write_res != TLS_REQUEST_LENGTH) {
          kprintf ("Failed to write request for checking domain %s: %s", domain, write_res == -1 ? strerror (errno) : "Written less bytes than expected");
          is_failed[i] = 1;
          completed_count++;
          continue;
        }
        is_written[i] = 1;
      }
      if (FD_ISSET(sockets[i], &except_fd)) {
        kprintf ("Failed to check domain %s: %s\n", domain, strerror (errno));
        is_failed[i] = 1;
        completed_count++;
        continue;
      }
      if (is_failed[i] && sockets[i] >= 0) {
        close (sockets[i]);
        sockets[i] = -1;
      }
    }
  }

  if (finished_count < MIN_PROBE_SUCCESSES) {
    if (!have_error) {
      kprintf ("Failed to check domain %s in 5 seconds: only %d/%d successful probe samples\n",
               domain, finished_count, TRIES);
    }
    goto cleanup;
  }

  // Build per-domain startup profiles and pick one per connection.
  free_domain_profiles (info);
  if (info->server_hello_template) {
    free (info->server_hello_template);
    info->server_hello_template = NULL;
  }
  info->server_hello_template_len = 0;
  info->server_hello_keyshare_offset = -1;
  info->server_hello_encrypted_size = 0;
  info->server_hello_encrypted_size2 = 0;
  info->server_hello_encrypted_size3 = 0;
  info->use_random_encrypted_size = 0;
  info->use_random_encrypted_size2 = 0;
  info->use_random_encrypted_size3 = 0;
  info->server_hello_encrypted_records = 1;
  info->is_reversed_extension_order = 0;

  int records_cnt_hist[8] = {};
  int rev_first = 0;
  int have_rev = 0;
  for (i = 0; i < TRIES; i++) {
    if (try_encrypted_application_data_records[i] <= 0) {
      continue;
    }
    int rc = try_encrypted_application_data_records[i];
    if (rc < 0) { rc = 0; }
    if (rc > 7) { rc = 7; }
    records_cnt_hist[rc]++;

    struct domain_profile cand;
    memset (&cand, 0, sizeof (cand));
    cand.encrypted_records = (char)try_encrypted_application_data_records[i];
    if (cand.encrypted_records < 1) { cand.encrypted_records = 1; }
    if (cand.encrypted_records > 3) { cand.encrypted_records = 3; }
    cand.is_reversed_extension_order = (char)try_is_reversed_extension_order[i];
    cand.encrypted_size[0] = (short)try_encrypted_application_data_lengths[i][0];
    cand.encrypted_size[1] = (short)try_encrypted_application_data_lengths[i][1];
    cand.encrypted_size[2] = (short)try_encrypted_application_data_lengths[i][2];
    cand.weight = 1;
    cand.server_hello_keyshare_offset = -1;
    cand.startup_payload_families_num = 0;
    domain_profile_note_startup_payload_family (
      &cand,
      tcp_rpc_collapse_startup_payload_size (cand.encrypted_records, try_encrypted_application_data_lengths[i])
    );

    if (extract_server_hello_template (responses[i], response_len[i], &cand.server_hello_template,
                                       &cand.server_hello_template_len, &cand.server_hello_keyshare_offset)) {
      int merged = 0;
      int p;
      for (p = 0; p < info->profiles_num; p++) {
        if (domain_profile_equals (&cand, &info->profiles[p])) {
          if (info->profiles[p].weight < 65535) {
            info->profiles[p].weight++;
          }
          domain_profile_merge_startup_payload_families (&info->profiles[p], &cand);
          free (cand.server_hello_template);
          cand.server_hello_template = NULL;
          merged = 1;
          break;
        }
      }
      if (!merged && info->profiles_num < DOMAIN_PROFILE_MAX) {
        info->profiles[info->profiles_num++] = cand;
        cand.server_hello_template = NULL;
      }
      free (cand.server_hello_template);
    }

    int rev = try_is_reversed_extension_order[i];
    if (!have_rev) {
      rev_first = rev;
      have_rev = 1;
      is_reversed_extension_order_min = rev;
      is_reversed_extension_order_max = rev;
    } else {
      if (rev < is_reversed_extension_order_min) { is_reversed_extension_order_min = rev; }
      if (rev > is_reversed_extension_order_max) { is_reversed_extension_order_max = rev; }
    }
  }

  if (have_rev && is_reversed_extension_order_min != is_reversed_extension_order_max) {
    kprintf ("Upstream server %s uses non-deterministic extension order\n", domain);
  }

  if (info->profiles_num > 0) {
    int best = 0;
    int p;
    for (p = 1; p < info->profiles_num; p++) {
      if (info->profiles[p].weight > info->profiles[best].weight) {
        best = p;
      }
    }

    const struct domain_profile *bp = &info->profiles[best];
    info->is_reversed_extension_order = bp->is_reversed_extension_order;
    info->server_hello_encrypted_records = bp->encrypted_records;
    info->server_hello_encrypted_size = bp->encrypted_size[0];
    info->server_hello_encrypted_size2 = bp->encrypted_size[1];
    info->server_hello_encrypted_size3 = bp->encrypted_size[2];
    info->server_hello_template_len = bp->server_hello_template_len;
    info->server_hello_keyshare_offset = bp->server_hello_keyshare_offset;
  } else {
    // Fall back to aggregate sizes if we could not capture at least one template.
    int best_records = 1, best_cnt = records_cnt_hist[1];
    int r;
    for (r = 2; r < 8; r++) {
      if (records_cnt_hist[r] > best_cnt) {
        best_cnt = records_cnt_hist[r];
        best_records = r;
      }
    }
    if (best_records < 1) { best_records = 1; }
    if (best_records > 3) { best_records = 3; }
    info->server_hello_encrypted_records = (char)best_records;
    info->is_reversed_extension_order = (char)(have_rev ? rev_first : 0);
    int cnt = 0;
    long long sum[3] = {0, 0, 0};
    for (i = 0; i < TRIES; i++) {
      if (try_encrypted_application_data_records[i] != best_records) {
        continue;
      }
      int k;
      for (k = 0; k < best_records && k < 3; k++) {
        sum[k] += try_encrypted_application_data_lengths[i][k];
      }
      cnt++;
    }
    info->server_hello_encrypted_size = (short)(cnt ? (sum[0] / cnt) : 2500);
    info->server_hello_encrypted_size2 = (short)(best_records >= 2 && cnt ? (sum[1] / cnt) : 0);
    info->server_hello_encrypted_size3 = (short)(best_records >= 3 && cnt ? (sum[2] / cnt) : 0);
    info->use_random_encrypted_size = 1;
  }

  vkprintf (0, "Successfully checked domain %s in %.3lf seconds using %d/%d probe samples: is_reversed_extension_order = %d, records = %d, size = %d,%d,%d\n",
            domain, get_utime_monotonic() - (finish_time - 5.0), finished_count, TRIES,
            info->is_reversed_extension_order, (int)info->server_hello_encrypted_records,
            info->server_hello_encrypted_size, info->server_hello_encrypted_size2, info->server_hello_encrypted_size3);

  ok = 1;
cleanup:
  for (i = 0; i < TRIES; i++) {
    if (sockets[i] >= 0) {
      close (sockets[i]);
    }
    free (requests[i]);
    free (responses[i]);
  }
  return ok;
#undef TRIES
#undef MIN_PROBE_SUCCESSES
}

#undef TLS_REQUEST_LENGTH

static const struct domain_info *get_sni_domain_info (const unsigned char *request, int len) {
#define CHECK_LENGTH(length)  \
  if (pos + (length) > len) { \
    return NULL;              \
  }

  int pos = 11 + 32 + 1 + 32;
  CHECK_LENGTH(2);
  int cipher_suites_length = read_length (request, &pos);
  CHECK_LENGTH(cipher_suites_length + 4);
  pos += cipher_suites_length + 4;
  while (1) {
    CHECK_LENGTH(4);
    int extension_id = read_length (request, &pos);
    int extension_length = read_length (request, &pos);
    CHECK_LENGTH(extension_length);

    if (extension_id == 0) {
      // found SNI
      CHECK_LENGTH(5);
      int inner_length = read_length (request, &pos);
      if (inner_length != extension_length - 2) {
        return NULL;
      }
      if (request[pos++] != 0) {
        return NULL;
      }
      int domain_length = read_length (request, &pos);
      if (domain_length != extension_length - 5) {
        return NULL;
      }
      int i;
      for (i = 0; i < domain_length; i++) {
        if (request[pos + i] == 0) {
          return NULL;
        }
      }
      const struct domain_info *info = get_domain_info ((const char *)(request + pos), domain_length);
      if (info == NULL) {
        vkprintf (1, "Receive request for unknown domain %.*s\n", domain_length, request + pos);
      }
      return info;
    }

    pos += extension_length;
  }
#undef CHECK_LENGTH
}

void tcp_rpc_add_proxy_domain (const char *domain) {
  assert (domain != NULL);

  struct domain_info *info = calloc (1, sizeof (struct domain_info));
  if (info == NULL) {
    kprintf ("Failed to allocate domain info for %s\n", domain);
    return;
  }
  info->domain = strdup (domain);
  if (info->domain == NULL) {
    kprintf ("Failed to allocate domain string for %s\n", domain);
    free (info);
    return;
  }

  struct domain_info **bucket = get_domain_info_bucket (domain, strlen (domain));
  info->next = *bucket;
  *bucket = info;

  if (!allow_only_tls) {
    allow_only_tls = 1;
    default_domain_info = info;
  }
}

void tcp_rpc_init_proxy_domains() {
  int i;
  for (i = 0; i < DOMAIN_HASH_MOD; i++) {
    struct domain_info *info = domains[i];
    while (info != NULL) {
      if (!update_domain_info (info)) {
        kprintf ("Failed to update response data about %s, so default response settings wiil be used\n", info->domain);
        free_domain_profiles (info);
        if (info->server_hello_template) {
          free (info->server_hello_template);
          info->server_hello_template = NULL;
        }
        info->server_hello_template_len = 0;
        info->server_hello_keyshare_offset = -1;
        // keep target addresses as is
        info->is_reversed_extension_order = 0;
        info->server_hello_encrypted_records = 1;
        info->use_random_encrypted_size = 1;
        info->server_hello_encrypted_size = 2500 + (int)((unsigned)lrand48_j () % 1120);
        info->use_random_encrypted_size2 = 0;
        info->use_random_encrypted_size3 = 0;
        info->server_hello_encrypted_size2 = 0;
        info->server_hello_encrypted_size3 = 0;
      }

      info = info->next;
    }
  }
}

static int is_ipv4_loopback (struct in_addr a) {
  // 127.0.0.0/8
  return (ntohl (a.s_addr) & 0xff000000U) == 0x7f000000U;
}

static int is_ipv6_loopback (const unsigned char a[16]) {
  static const unsigned char loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  return memcmp (a, loopback, 16) == 0;
}

int tcp_rpc_set_fallback_backend (const char *backend) {
  if (backend == NULL || *backend == 0) {
    return -1;
  }

  char host[256];
  char serv[16];
  memset (host, 0, sizeof (host));
  memset (serv, 0, sizeof (serv));

  if (backend[0] == '[') {
    // [ipv6]:port
    const char *end = strchr (backend, ']');
    if (end == NULL || end[1] != ':' || end[2] == 0) {
      return -2;
    }
    size_t hlen = (size_t)(end - backend - 1);
    if (hlen == 0 || hlen >= sizeof (host)) {
      return -3;
    }
    memcpy (host, backend + 1, hlen);
    snprintf (serv, sizeof (serv), "%s", end + 2);
  } else {
    // host:port (ipv6 must be bracketed)
    const char *colon = strrchr (backend, ':');
    if (colon == NULL || colon[1] == 0) {
      return -4;
    }
    if (strchr (backend, ':') != colon) {
      // multiple ':' -> looks like unbracketed ipv6
      return -5;
    }
    size_t hlen = (size_t)(colon - backend);
    if (hlen == 0 || hlen >= sizeof (host)) {
      return -6;
    }
    memcpy (host, backend, hlen);
    snprintf (serv, sizeof (serv), "%s", colon + 1);
  }

  int port = atoi (serv);
  if (port <= 0 || port > 65535) {
    return -7;
  }

  struct addrinfo hints;
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

  struct addrinfo *res = NULL;
  int err = getaddrinfo (host, serv, &hints, &res);
  if (err != 0 || res == NULL) {
    return -8;
  }

  struct addrinfo *ai = res;
  for (; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
      break;
    }
  }
  if (ai == NULL) {
    freeaddrinfo (res);
    return -9;
  }

  struct in_addr target4;
  unsigned char target6[16];
  int is_ipv6 = 0;
  memset (&target4, 0, sizeof (target4));
  memset (target6, 0, sizeof (target6));

  if (ai->ai_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
    target4 = sin->sin_addr;
    is_ipv6 = 0;
    if (!is_ipv4_loopback (target4)) {
      freeaddrinfo (res);
      return -10;
    }
  } else {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
    memcpy (target6, &sin6->sin6_addr, 16);
    is_ipv6 = 1;
    if (!is_ipv6_loopback (target6)) {
      freeaddrinfo (res);
      return -10;
    }
  }

  freeaddrinfo (res);

  memset (&fallback_backend_target, 0, sizeof (fallback_backend_target));
  memset (fallback_backend_target_ipv6, 0, sizeof (fallback_backend_target_ipv6));
  fallback_backend_is_ipv6 = is_ipv6;
  fallback_backend_port = port;
  snprintf (fallback_backend_printable, sizeof (fallback_backend_printable), "%s", backend);
  if (!fallback_backend_is_ipv6) {
    fallback_backend_target = target4;
  } else {
    memcpy (fallback_backend_target_ipv6, target6, 16);
  }

  fallback_backend_enabled = 1;
  return 0;
}

int tcp_rpc_fallback_backend_enabled (void) {
  return fallback_backend_enabled;
}

void tcp_rpc_enable_fallback_relay (void) {
  fallback_relay_enabled = 1;
}

int tcp_rpc_fallback_relay_enabled (void) {
  return fallback_relay_enabled;
}

static int ip_acl_set_file (ip_acl_source_t *src, const char *filename) {
  if (!filename || !*filename) {
    return -1;
  }

  ip_acl_set_t *set = 0;
  long long mtime = 0;
  long long size = 0;
  if (ip_acl_load_file (filename, &set, &mtime, &size) < 0) {
    return -2;
  }

  char *path = strdup (filename);
  if (!path) {
    ip_acl_free_set (set);
    return -3;
  }

  pthread_rwlock_wrlock (&ip_acl_lock);
  char *old_path = src->path;
  ip_acl_set_t *old_set = src->set;
  src->path = path;
  src->set = set;
  src->mtime = mtime;
  src->size = size;
  ip_acl_next_refresh_time = 0;
  pthread_rwlock_unlock (&ip_acl_lock);

  free (old_path);
  ip_acl_free_set (old_set);
  __atomic_fetch_add (&tls_ip_acl_refresh_success, 1, __ATOMIC_RELAXED);
  return 0;
}

int tcp_rpc_set_ip_blocklist_file (const char *filename) {
  return ip_acl_set_file (&ip_blocklist, filename);
}

int tcp_rpc_set_ip_allowlist_file (const char *filename) {
  return ip_acl_set_file (&ip_allowlist, filename);
}

void tcp_rpc_set_ip_acl_refresh_interval (int seconds) {
  if (seconds < 0) {
    seconds = 0;
  } else if (seconds > 86400) {
    seconds = 86400;
  }
  ip_acl_refresh_interval = seconds;
}

void tcp_rpc_refresh_ip_acl (void) {
  if (ip_acl_refresh_interval <= 0) {
    return;
  }
  int ts = now ? now : (int)time (0);
  if (ip_acl_next_refresh_time && ts < ip_acl_next_refresh_time) {
    return;
  }
  ip_acl_next_refresh_time = ts + ip_acl_refresh_interval;
  int r = ip_acl_reload_all (0);
  if (r > 0) {
    __atomic_fetch_add (&tls_ip_acl_refresh_success, 1, __ATOMIC_RELAXED);
  } else if (r < 0) {
    __atomic_fetch_add (&tls_ip_acl_refresh_fail, 1, __ATOMIC_RELAXED);
  }
}

void tcp_rpc_set_secret_max_unique_ips (int limit) {
  max_secret_unique_ips = limit > 0 ? limit : 0;
}

void tcp_rpc_set_secret_max_connections (int limit) {
  max_secret_connections = limit > 0 ? limit : 0;
}

void tcp_rpc_set_secret_max_total_octets (unsigned long long limit) {
  max_secret_total_octets = limit;
}

void tcp_rpc_set_client_handshake_timeout (int timeout_seconds) {
  if (timeout_seconds < 1) {
    timeout_seconds = 1;
  } else if (timeout_seconds > 60) {
    timeout_seconds = 60;
  }
  client_handshake_timeout = timeout_seconds;
}

void tcp_rpc_set_replay_cache_max_entries (int limit) {
  if (limit < 1) {
    limit = 1;
  } else if (limit > 5000000) {
    limit = 5000000;
  }
  replay_cache_max_entries = limit;
}

void tcp_rpc_set_replay_cache_max_age (int seconds) {
  if (seconds < 1) {
    seconds = 1;
  } else if (seconds > 30 * 86400) {
    seconds = 30 * 86400;
  }
  replay_cache_max_age = seconds;
}

void tcp_rpc_set_replay_cache_max_bytes (unsigned long long bytes_limit) {
  if (bytes_limit > 0 && bytes_limit < 64) {
    bytes_limit = 64;
  }
  replay_cache_max_bytes = bytes_limit;
}

void tcp_rpc_set_undetermined_conns_limit (int limit) {
  if (limit < 1) {
    limit = 1;
  } else if (limit > 1000000) {
    limit = 1000000;
  }
  max_undetermined_conns = limit;
}

void tcp_rpc_set_undetermined_conns_global_limit (int limit) {
  if (limit < 1) {
    limit = 1;
  } else if (limit > 10000000) {
    limit = 10000000;
  }
  max_undetermined_conns_global = limit;
}

void tcp_rpc_set_undetermined_buffer_bytes_limit (int limit) {
  if (limit < 256) {
    limit = 256;
  } else if (limit > (1 << 20)) {
    limit = (1 << 20);
  }
  max_undetermined_buffer_bytes = limit;
}

void tcp_rpc_set_undetermined_bytes_global_limit (long long limit) {
  if (limit < (1 << 20)) {
    limit = (1 << 20);
  } else if (limit > (1LL << 36)) {
    limit = (1LL << 36);
  }
  max_undetermined_bytes_global = limit;
}

void tcp_rpc_set_undetermined_conns_per_ip_limit (int limit) {
  if (limit < 0) {
    limit = 0;
  } else if (limit > 65535) {
    limit = 65535;
  }
  max_undetermined_conns_per_ip = limit;
}

struct client_random {
  unsigned char random[16];
  struct client_random *next_by_time;
  struct client_random *next_by_hash;
  int time;
};

#define RANDOM_HASH_BITS 14
static struct client_random *client_randoms[1 << RANDOM_HASH_BITS];

static struct client_random *first_client_random;
static struct client_random *last_client_random;
static int client_random_count;

static unsigned long long replay_cache_estimated_bytes (void) {
  return (unsigned long long)client_random_count * (unsigned long long)sizeof (struct client_random);
}

static struct client_random **get_client_random_bucket (unsigned char random[16]) {
  int i = RANDOM_HASH_BITS;
  int pos = 0;
  int id = 0;
  while (i > 0) {
    int bits = i < 8 ? i : 8;
    id = (id << bits) | (random[pos++] & ((1 << bits) - 1));
    i -= bits;
  }
  assert (0 <= id && id < (1 << RANDOM_HASH_BITS));
  return client_randoms + id;
}

static int have_client_random (unsigned char random[16]) {
  __atomic_fetch_add (&tls_replay_cache_checks, 1, __ATOMIC_RELAXED);
  struct client_random *cur = *get_client_random_bucket (random);
  while (cur != NULL) {
    if (memcmp (random, cur->random, 16) == 0) {
      __atomic_fetch_add (&tls_replay_cache_hits, 1, __ATOMIC_RELAXED);
      return 1;
    }
    cur = cur->next_by_hash;
  }
  return 0;
}

static void trim_client_randoms_limit (void);

static int add_client_random (unsigned char random[16]) {
  struct client_random *entry = malloc (sizeof (struct client_random));
  if (entry == NULL) {
    vkprintf (0, "failed to allocate client_random cache entry\n");
    return -1;
  }
  memcpy (entry->random, random, 16);
  entry->time = now;
  entry->next_by_time = NULL;
  if (last_client_random == NULL) {
    assert (first_client_random == NULL);
    first_client_random = last_client_random = entry;
  } else {
    last_client_random->next_by_time = entry;
    last_client_random = entry;
  }

  struct client_random **bucket = get_client_random_bucket (random);
  entry->next_by_hash = *bucket;
  *bucket = entry;

  client_random_count++;
  __atomic_fetch_add (&tls_replay_cache_entries, 1, __ATOMIC_RELAXED);
  __atomic_fetch_add (&tls_replay_cache_additions, 1, __ATOMIC_RELAXED);
  trim_client_randoms_limit ();
  return 0;
}

static void delete_client_random_head (void) {
  struct client_random *entry = first_client_random;
  if (!entry) {
      return;
    }

  first_client_random = entry->next_by_time;
  if (last_client_random == entry) {
    last_client_random = first_client_random;
  }

    struct client_random **cur = get_client_random_bucket (entry->random);
  while (*cur && *cur != entry) {
      cur = &(*cur)->next_by_hash;
    }
  if (*cur == entry) {
    *cur = entry->next_by_hash;
  }

    free (entry);
  if (client_random_count > 0) {
    client_random_count--;
    __atomic_fetch_sub (&tls_replay_cache_entries, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add (&tls_replay_cache_evictions, 1, __ATOMIC_RELAXED);
  }
}

static void trim_client_randoms_limit (void) {
  while (first_client_random) {
    int over_entries = client_random_count > replay_cache_max_entries;
    int over_bytes = replay_cache_max_bytes > 0 && replay_cache_estimated_bytes () > replay_cache_max_bytes;
    if (!over_entries && !over_bytes) {
      break;
    }
    delete_client_random_head ();
  }
}

static void delete_old_client_randoms (void) {
  while (first_client_random && first_client_random->time <= now - replay_cache_max_age) {
    delete_client_random_head ();
  }
}

void tcp_rpc_ext_replay_cache_cleanup (void) {
  delete_old_client_randoms ();
  trim_client_randoms_limit ();
}

static int is_allowed_timestamp (int timestamp) {
  if (timestamp > now + 3) {
    // do not allow timestamps in the future
    // after time synchronization client should always have time in the past
    vkprintf (1, "Disallow request with timestamp %d from the future, now is %d\n", timestamp, now);
    return 0;
  }

  // first_client_random->time is an exact time when corresponding request was received
  // if the timestamp is bigger than (first_client_random->time + 3), then the current request could be accepted
  // only after the request with first_client_random, so the client random still must be cached
  // if the request wasn't accepted, then the client_random still will be cached for replay_cache_max_age seconds,
  // so we can miss duplicate request only after a lot of time has passed
  if (first_client_random != NULL && timestamp > first_client_random->time + 3) {
    vkprintf (1, "Allow new request with timestamp %d\n", timestamp);
    return 1;
  }

  // allow all requests with timestamp recently in past, regardless of ability to check repeating client random
  // the allowed error must be big enough to allow requests after time synchronization
  const int MAX_ALLOWED_TIMESTAMP_ERROR = 10 * 60;
  if (timestamp > now - MAX_ALLOWED_TIMESTAMP_ERROR) {
    // this can happen only first (MAX_ALLOWED_TIMESTAMP_ERROR + 3) sceonds after first_client_random->time
    vkprintf (1, "Allow recent request with timestamp %d without full check for client random duplication\n", timestamp);
    return 1;
  }

  // the request is too old to check client random, do not allow it to force client to synchronize it's time
  vkprintf (1, "Disallow too old request with timestamp %d\n", timestamp);
  return 0;
}

// Per-thread invalid-traffic throttling (cheap, lock-free, best-effort).
// This aims to make repeated invalid TLS handshakes expensive without affecting real clients.
struct probe_entry {
  unsigned ip4;
  unsigned char ip6[16];
  int is_ipv6;
  int score;
  int last_time;
  int blocked_until;
};
static __thread struct probe_entry probe_table[PROBE_TABLE_SIZE];
static __thread struct probe_entry probe_net_table[PROBE_TABLE_SIZE];

static unsigned probe_hash4 (unsigned ip4) {
  // Knuth multiplicative hash.
  return (ip4 * 2654435761u) >> (32 - MT_TLS_PROBE_TABLE_BITS);
}

static unsigned probe_hash6 (const unsigned char ip6[16]) {
  // Avoid unaligned reads / strict-aliasing UB on some architectures.
  unsigned w[4];
  memcpy (w, ip6, 16);
  unsigned h = w[0] ^ w[1] ^ w[2] ^ w[3];
  return (h * 2654435761u) >> (32 - MT_TLS_PROBE_TABLE_BITS);
}

static unsigned probe_ipv4_prefix24 (unsigned ip4_host) {
  // Normalize to /24 in a byte-order independent way.
  unsigned ip4_net = htonl (ip4_host);
  ip4_net &= 0xffffff00U;
  return ntohl (ip4_net);
}

static void probe_ipv6_prefix64 (unsigned char out[16], const unsigned char in[16]) {
  memcpy (out, in, 16);
  memset (out + 8, 0, 8);
}

#define SECRET_IP_TABLE_SIZE (1u << 12)
struct secret_ip_entry {
  unsigned ip4;
  unsigned char ip6[16];
  unsigned short refs;
  unsigned char secret_slot;
  unsigned char is_ipv6;
  unsigned char state; // 0 = empty, 1 = used, 2 = tombstone
};
static __thread struct secret_ip_entry secret_ip_table[SECRET_IP_TABLE_SIZE];
static __thread int secret_unique_ip_count[EXT_SECRET_MAX];

static int conn_get_secret_slot (connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  int marker = (int)D->extra_double2;
  return marker > 0 ? marker - 1 : -1;
}

static void conn_set_secret_slot (connection_job_t C, int secret_slot) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  D->extra_double2 = secret_slot >= 0 ? (double)(secret_slot + 1) : 0.0;
}

static unsigned secret_ip_hash (int secret_slot, unsigned ip4, const unsigned char ip6[16], int is_ipv6) {
  unsigned h = (unsigned)secret_slot * 2246822519u;
  h ^= !is_ipv6 ? probe_hash4 (ip4) : probe_hash6 (ip6);
  return h & (SECRET_IP_TABLE_SIZE - 1);
}

static int secret_ip_entry_match (const struct secret_ip_entry *e, int secret_slot, unsigned ip4, const unsigned char ip6[16], int is_ipv6) {
  if (e->state != 1 || e->secret_slot != (unsigned char)secret_slot || e->is_ipv6 != (unsigned char)is_ipv6) {
    return 0;
  }
  if (!is_ipv6) {
    return e->ip4 == ip4;
  }
  return !memcmp (e->ip6, ip6, 16);
}

static int secret_ip_limit_enter (connection_job_t C, int secret_slot) {
  if (max_secret_unique_ips <= 0 || secret_slot < 0 || secret_slot >= EXT_SECRET_MAX) {
    return 0;
  }
  if (conn_get_secret_slot (C) >= 0) {
    return 0;
  }
  struct connection_info *c = CONN_INFO (C);
  unsigned ip4 = c->remote_ip;
  unsigned char ip6[16];
  int is_ipv6 = c->remote_ip ? 0 : 1;
  if (is_ipv6) {
    memcpy (ip6, c->remote_ipv6, 16);
  } else {
    memset (ip6, 0, 16);
  }

  unsigned idx = secret_ip_hash (secret_slot, ip4, ip6, is_ipv6);
  int i;
  int tomb = -1;
  for (i = 0; i < (int)SECRET_IP_TABLE_SIZE; i++) {
    struct secret_ip_entry *e = &secret_ip_table[(idx + i) & (SECRET_IP_TABLE_SIZE - 1)];
    if (e->state == 0) {
      if (secret_unique_ip_count[secret_slot] >= max_secret_unique_ips) {
        __atomic_fetch_add (&tls_secret_unique_ip_rejects, 1, __ATOMIC_RELAXED);
        return -1;
      }
      if (tomb >= 0) {
        e = &secret_ip_table[tomb];
      }
      e->state = 1;
      e->secret_slot = (unsigned char)secret_slot;
      e->is_ipv6 = (unsigned char)is_ipv6;
      e->ip4 = ip4;
      memcpy (e->ip6, ip6, 16);
      e->refs = 1;
      secret_unique_ip_count[secret_slot]++;
      conn_set_secret_slot (C, secret_slot);
      return 0;
    }
    if (e->state == 2) {
      if (tomb < 0) {
        tomb = (idx + i) & (SECRET_IP_TABLE_SIZE - 1);
      }
      continue;
    }
    if (secret_ip_entry_match (e, secret_slot, ip4, ip6, is_ipv6)) {
      if (e->refs < 0xffff) {
        e->refs++;
      }
      conn_set_secret_slot (C, secret_slot);
      return 0;
    }
  }

  __atomic_fetch_add (&tls_secret_unique_ip_rejects, 1, __ATOMIC_RELAXED);
  return -1;
}

static void secret_ip_limit_leave (connection_job_t C) {
  int secret_slot = conn_get_secret_slot (C);
  if (max_secret_unique_ips <= 0 || secret_slot < 0 || secret_slot >= EXT_SECRET_MAX) {
    conn_set_secret_slot (C, -1);
    return;
  }
  struct connection_info *c = CONN_INFO (C);
  unsigned ip4 = c->remote_ip;
  unsigned char ip6[16];
  int is_ipv6 = c->remote_ip ? 0 : 1;
  if (is_ipv6) {
    memcpy (ip6, c->remote_ipv6, 16);
  } else {
    memset (ip6, 0, 16);
  }

  unsigned idx = secret_ip_hash (secret_slot, ip4, ip6, is_ipv6);
  int i;
  for (i = 0; i < (int)SECRET_IP_TABLE_SIZE; i++) {
    struct secret_ip_entry *e = &secret_ip_table[(idx + i) & (SECRET_IP_TABLE_SIZE - 1)];
    if (e->state == 0) {
      break;
    }
    if (secret_ip_entry_match (e, secret_slot, ip4, ip6, is_ipv6)) {
      if (e->refs > 1) {
        e->refs--;
      } else {
        e->refs = 0;
        e->state = 2;
        if (secret_unique_ip_count[secret_slot] > 0) {
          secret_unique_ip_count[secret_slot]--;
        }
      }
      break;
    }
  }
  conn_set_secret_slot (C, -1);
}

static int secret_conn_limit_enter (connection_job_t C) {
  int secret_slot = conn_get_secret_slot (C);
  if (secret_slot < 0 || secret_slot >= EXT_SECRET_MAX) {
    return 0;
  }
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->extra_int & EXT_TCPRPC_F_SECRET_CONN_COUNTED) {
    return 0;
  }
  if (max_secret_connections > 0 && secret_conn_count[secret_slot] >= (unsigned int)max_secret_connections) {
    __atomic_fetch_add (&tls_secret_conn_limit_rejects, 1, __ATOMIC_RELAXED);
    return -1;
  }
  if (max_secret_total_octets > 0 && secret_total_octets[secret_slot] >= max_secret_total_octets) {
    __atomic_fetch_add (&tls_secret_total_octet_rejects, 1, __ATOMIC_RELAXED);
    return -1;
  }
  secret_conn_count[secret_slot]++;
  D->extra_int |= EXT_TCPRPC_F_SECRET_CONN_COUNTED;
  return 0;
}

static void secret_conn_limit_leave (connection_job_t C) {
  int secret_slot = conn_get_secret_slot (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (!(D->extra_int & EXT_TCPRPC_F_SECRET_CONN_COUNTED)) {
    return;
  }
  D->extra_int &= ~(EXT_TCPRPC_F_SECRET_CONN_COUNTED | EXT_TCPRPC_F_SECRET_QUOTA_HIT);
  if (secret_slot >= 0 && secret_slot < EXT_SECRET_MAX && secret_conn_count[secret_slot] > 0) {
    secret_conn_count[secret_slot]--;
  }
}

static void secret_octet_quota_note (connection_job_t C, int bytes) {
  if (bytes <= 0) {
    return;
  }
  int secret_slot = conn_get_secret_slot (C);
  if (secret_slot < 0 || secret_slot >= EXT_SECRET_MAX) {
    return;
  }
  unsigned long long prev = __atomic_fetch_add (&secret_total_octets[secret_slot], (unsigned long long)bytes, __ATOMIC_RELAXED);
  if (max_secret_total_octets > 0 && prev + (unsigned long long)bytes > max_secret_total_octets) {
    struct tcp_rpc_data *D = TCP_RPC_DATA (C);
    if (!(D->extra_int & EXT_TCPRPC_F_SECRET_QUOTA_HIT)) {
      D->extra_int |= EXT_TCPRPC_F_SECRET_QUOTA_HIT;
      __atomic_fetch_add (&tls_secret_total_octet_rejects, 1, __ATOMIC_RELAXED);
    }
    fail_connection (C, -1);
  }
}

void tcp_rpc_secret_note_data_received (connection_job_t C, int bytes_received) {
  secret_octet_quota_note (C, bytes_received);
}

void tcp_rpc_secret_note_data_sent (connection_job_t C, int bytes_sent) {
  secret_octet_quota_note (C, bytes_sent);
}

static int probe_match (const struct probe_entry *e, const struct connection_info *c) {
  if (!e->last_time) {
    return 0;
  }
  if (c->remote_ip) {
    return !e->is_ipv6 && e->ip4 == c->remote_ip;
  }
  return e->is_ipv6 && !memcmp (e->ip6, c->remote_ipv6, 16);
}

static int probe_match_key (const struct probe_entry *e, unsigned ip4, const unsigned char ip6[16], int is_ipv6) {
  if (!e->last_time) {
    return 0;
  }
  if (!is_ipv6) {
    return !e->is_ipv6 && e->ip4 == ip4;
  }
  return e->is_ipv6 && !memcmp (e->ip6, ip6, 16);
}

static void probe_set_key (struct probe_entry *e, const struct connection_info *c) {
  if (c->remote_ip) {
    e->is_ipv6 = 0;
    e->ip4 = c->remote_ip;
    memset (e->ip6, 0, 16);
  } else {
    e->is_ipv6 = 1;
    e->ip4 = 0;
    memcpy (e->ip6, c->remote_ipv6, 16);
  }
}

static void probe_set_key_key (struct probe_entry *e, unsigned ip4, const unsigned char ip6[16], int is_ipv6) {
  e->is_ipv6 = is_ipv6;
  if (!is_ipv6) {
    e->ip4 = ip4;
    memset (e->ip6, 0, 16);
  } else {
    e->ip4 = 0;
    memcpy (e->ip6, ip6, 16);
  }
}

static struct probe_entry *probe_get_entry_tbl (struct probe_entry *tbl, const struct connection_info *c) {
  unsigned idx = c->remote_ip ? probe_hash4 (c->remote_ip) : probe_hash6 (c->remote_ipv6);
  unsigned i;
  struct probe_entry *evict = NULL;
  int evict_score = 0;
  int evict_last_time = 0;
  for (i = 0; i < 16; i++) {
    struct probe_entry *e = &tbl[(idx + i) & (PROBE_TABLE_SIZE - 1)];
    if (!e->last_time) {
      probe_set_key (e, c);
      __atomic_fetch_add (&tls_probe_table_ip_used, 1, __ATOMIC_RELAXED);
      return e;
    }
    if (probe_match (e, c)) {
      return e;
    }
    if (evict == NULL || e->score < evict_score || (e->score == evict_score && e->last_time < evict_last_time)) {
      evict = e;
      evict_score = e->score;
      evict_last_time = e->last_time;
    }
  }
  // Table is saturated in this window; evict the least valuable entry.
  struct probe_entry *e = evict ? evict : &tbl[idx & (PROBE_TABLE_SIZE - 1)];
  probe_set_key (e, c);
  e->score = 0;
  e->blocked_until = 0;
  e->last_time = 0;
  return e;
}

static struct probe_entry *probe_get_entry_net (const struct connection_info *c) {
  unsigned ip4 = 0;
  unsigned char ip6[16];
  int is_ipv6 = 0;
  memset (ip6, 0, 16);
  if (c->remote_ip) {
    ip4 = probe_ipv4_prefix24 (c->remote_ip);
    is_ipv6 = 0;
  } else {
    probe_ipv6_prefix64 (ip6, c->remote_ipv6);
    is_ipv6 = 1;
  }

  unsigned idx = !is_ipv6 ? probe_hash4 (ip4) : probe_hash6 (ip6);
  unsigned i;
  struct probe_entry *evict = NULL;
  int evict_score = 0;
  int evict_last_time = 0;
  for (i = 0; i < 16; i++) {
    struct probe_entry *e = &probe_net_table[(idx + i) & (PROBE_TABLE_SIZE - 1)];
    if (!e->last_time) {
      probe_set_key_key (e, ip4, ip6, is_ipv6);
      __atomic_fetch_add (&tls_probe_table_net_used, 1, __ATOMIC_RELAXED);
      return e;
    }
    if (probe_match_key (e, ip4, ip6, is_ipv6)) {
      return e;
    }
    if (evict == NULL || e->score < evict_score || (e->score == evict_score && e->last_time < evict_last_time)) {
      evict = e;
      evict_score = e->score;
      evict_last_time = e->last_time;
    }
  }
  struct probe_entry *e = evict ? evict : &probe_net_table[idx & (PROBE_TABLE_SIZE - 1)];
  probe_set_key_key (e, ip4, ip6, is_ipv6);
  e->score = 0;
  e->blocked_until = 0;
  e->last_time = 0;
  return e;
}

static int probe_entry_note_failure (struct probe_entry *e, int weight, int *blocked) {
  const int t = now;
  if (e->blocked_until > t) {
    // While blocked, do not refresh decay anchors; otherwise background probe
    // noise can keep postponing effective recovery for shared subnets.
    *blocked = 1;
    return 0;
  }

  if (e->last_time > 0) {
    int dt = t - e->last_time;
    if (dt < 0) { dt = 0; }
    if (dt > 0) {
      // Decay score quickly so occasional mistakes don't penalize.
      long long decay = (long long) dt * 2;
      if (decay >= e->score) {
        e->score = 0;
      } else {
        e->score -= (int) decay;
      }
    }
  }
  e->last_time = t;

  if (weight < 1) { weight = 1; }
  if (weight > 10) { weight = 10; }
  e->score += weight;

  // If we see many failures in a short period, block for a while.
  if (e->score >= 20) {
    int block_s = 15 + (e->score - 20);
    if (block_s > 60) { block_s = 60; }
    e->blocked_until = t + block_s;
    *blocked = 1;
    return 0;
  }

  *blocked = 0;
  if (e->score <= 4) {
    return 0;
  }
  if (e->score <= 6) {
    // Keep low-score failures mostly cheap, with occasional small delay.
    unsigned int r = (unsigned int) lrand48_j ();
    if ((r & 3) != 0) { // ~75% immediate close
      return 0;
    }
    return 2 + (int)((r >> 2) % 9); // 2..10ms
  }

  // Above low score, use a smoother delay curve with wider jitter.
  int d = (e->score - 6) * 18;
  d += (int)(lrand48_j () % 61) - 15; // -15..45ms jitter
  if (d < 0) { d = 0; }
  if (d > 200) { d = 200; }
  return d;
}

// Returns delay in ms (0..200). Sets *blocked=1 if we should hard-drop this attempt.
static int probe_note_failure (connection_job_t C, int weight, int *blocked) {
  struct connection_info *c = CONN_INFO (C);
  struct probe_entry *e_ip = probe_get_entry_tbl (probe_table, c);
  struct probe_entry *e_net = probe_get_entry_net (c);

  int blocked_ip = 0, blocked_net = 0;
  int d_ip = probe_entry_note_failure (e_ip, weight, &blocked_ip);
  // Be conservative at subnet level to reduce false positives (NAT): always weight 1.
  int d_net = probe_entry_note_failure (e_net, 1, &blocked_net);

  *blocked = blocked_ip || blocked_net;
  int d = d_ip > d_net ? d_ip : d_net;
  probe_stat_note (*blocked, d);
  return d;
}

static void best_effort_send_plain (connection_job_t C, const void *buf, int len) {
  if (len <= 0 || buf == NULL) {
    return;
  }
  struct connection_info *c = CONN_INFO (C);
  int fd = c->fd;
  if (fd < 0 && c->io_conn) {
    fd = SOCKET_CONN_INFO (c->io_conn)->fd;
  }
  if (fd < 0) {
    return;
  }
  int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  (void)send (fd, buf, (size_t)len, flags);
}

static int tls_send_alert_and_close (connection_job_t C, unsigned char description) {
  // Pre-auth reject path must not allocate.
  static const unsigned char alert_tpl[7] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}; // fatal handshake_failure
  static const unsigned char alert_versions[][2] = {
    {0x03, 0x01},
    {0x03, 0x02},
    {0x03, 0x03}
  };
  unsigned char alert[7];
  memcpy (alert, alert_tpl, sizeof (alert));
  unsigned int vi = (unsigned int) lrand48_j () % (sizeof (alert_versions) / sizeof (alert_versions[0]));
  alert[1] = alert_versions[vi][0];
  alert[2] = alert_versions[vi][1];
  alert[6] = description;
  best_effort_send_plain (C, alert, (int)sizeof (alert));
  connection_write_close (C);
  return NEED_MORE_BYTES;
}

static int http_send_301_and_close (connection_job_t C) {
  // For plain HTTP on a TLS-only port, reply with a simple redirect
  // to the configured default -D domain.
  struct connection_info *c = CONN_INFO (C);

  const char *host = (default_domain_info && default_domain_info->domain) ? default_domain_info->domain : "example.com";
  char path[1024];
  strcpy (path, "/");

  // Best-effort path extraction: METHOD SP <path> SP HTTP/...
  int avail = c->in.total_bytes;
  if (avail > 0) {
    if (avail > 2047) {
      avail = 2047;
    }
    unsigned char buf[2048];
    if (rwm_fetch_lookup (&c->in, buf, avail) == avail) {
      int i;
      // Find first space after method token
      for (i = 0; i < avail && buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\n'; i++) {}
      if (i < avail && buf[i] == ' ') {
        int j = i + 1;
        while (j < avail && buf[j] == ' ') { j++; }
        int k = j;
        while (k < avail && buf[k] != ' ' && buf[k] != '\r' && buf[k] != '\n') { k++; }
        if (k > j) {
          int n = k - j;
          if (n > (int)sizeof (path) - 1) {
            n = (int)sizeof (path) - 1;
          }
          memcpy (path, buf + j, n);
          path[n] = 0;
          if (path[0] != '/') {
            // Absolute-form or garbage; don't reflect it.
            strcpy (path, "/");
          }
        }
      }
    }
  }

  char location[2048];
  snprintf (location, sizeof (location), "https://%s%s", host, path);

  char resp[4096];
  int rlen = snprintf (resp, sizeof (resp),
                       "HTTP/1.1 301 Moved Permanently\r\n"
                       "Location: %s\r\n"
                       "Content-Length: 0\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       location);
  if (rlen < 0) {
    rlen = 0;
  }
  if (rlen > (int)sizeof (resp)) {
    rlen = (int)sizeof (resp);
  }

  best_effort_send_plain (C, resp, rlen);
  connection_write_close (C);
  return NEED_MORE_BYTES;
}

static int proxy_connection_fallback (connection_job_t C);
static int proxy_connection (connection_job_t C, const struct domain_info *info);

static void stop_reading_temporarily (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  socket_connection_job_t S = c->io_conn;
  if (S) {
    __sync_fetch_and_or (&SOCKET_CONN_INFO(S)->flags, C_STOPREAD);
  }
  __sync_fetch_and_or (&c->flags, C_STOPREAD | C_STOPPARSE);
}

static int adjust_reject_delay_ms (int delay_ms) {
  if (delay_ms < 10) {
    return delay_ms;
  }
  int jitter = (int)((unsigned int) lrand48_j () % 101) - 50; // -50..+50ms
  int out = delay_ms + jitter;
  if (out < 50) {
    out = 50;
  } else if (out > 500) {
    out = 500;
  }
  return out;
}

enum {
  TLS_DELAY_ACTION_NONE = 0,
  TLS_DELAY_ACTION_ALERT = 1,
  TLS_DELAY_ACTION_CLOSE = 2,
  TLS_DELAY_ACTION_RUN = 3
};

static int tls_schedule_delayed_alert (connection_job_t C, unsigned char alert_description, int delay_ms) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->extra_int2 != TLS_DELAY_ACTION_NONE) {
    return NEED_MORE_BYTES;
  }
  delay_ms = adjust_reject_delay_ms (delay_ms);
  if (D->in_packet_num == -3) {
    // Once we decided to reject this connection, it is no longer "undetermined".
    undetermined_conn_leave (C);
  }
  if (delay_ms <= 0) {
    return tls_send_alert_and_close (C, alert_description);
  }
  __atomic_fetch_add (&tls_delayed_reject_alert, 1, __ATOMIC_RELAXED);
  D->extra_int2 = TLS_DELAY_ACTION_ALERT;
  D->extra_int3 = (int)alert_description;
  stop_reading_temporarily (C);
  job_timer_insert (C, precise_now + 0.001 * delay_ms);
  return NEED_MORE_BYTES;
}

static int tls_schedule_delayed_close (connection_job_t C, int delay_ms) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->extra_int2 != TLS_DELAY_ACTION_NONE) {
    return NEED_MORE_BYTES;
  }
  delay_ms = adjust_reject_delay_ms (delay_ms);
  if (D->in_packet_num == -3) {
    // Once we decided to reject this connection, it is no longer "undetermined".
    undetermined_conn_leave (C);
  }
  if (delay_ms <= 0) {
    connection_write_close (C);
    return NEED_MORE_BYTES;
  }
  __atomic_fetch_add (&tls_delayed_reject_close, 1, __ATOMIC_RELAXED);
  D->extra_int2 = TLS_DELAY_ACTION_CLOSE;
  D->extra_int3 = 0;
  stop_reading_temporarily (C);
  job_timer_insert (C, precise_now + 0.001 * delay_ms);
  return NEED_MORE_BYTES;
}

static int input_looks_like_tls_handshake (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  if (c->flags & C_IS_TLS) {
    return 1;
  }
  if (c->in.total_bytes < 3) {
    return 0;
  }
  unsigned char pfx[3];
  if (rwm_fetch_lookup (&c->in, pfx, 3) != 3) {
    return 0;
  }
  // TLS Handshake record (content-type 22), TLS family version marker (0x03 xx).
  return pfx[0] == 0x16 && pfx[1] == 0x03 && pfx[2] <= 0x04;
}

static int tls_schedule_delayed_reject (connection_job_t C, int delay_ms, unsigned char alert_description) {
  if (input_looks_like_tls_handshake (C)) {
    return tls_schedule_delayed_alert (C, alert_description, delay_ms);
  }
  return tls_schedule_delayed_close (C, delay_ms);
}

static int tls_schedule_blocked_reject (connection_job_t C, unsigned char alert_description) {
  // Keep blocked rejects cheap, but avoid perfectly deterministic zero-delay closes.
  int delay_ms = 1 + ((unsigned int) lrand48_j () % 6); // 1..6ms
  return tls_schedule_delayed_reject (C, delay_ms, alert_description);
}

static int tls_schedule_delayed_run (connection_job_t C, int delay_ms) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->extra_int2 != TLS_DELAY_ACTION_NONE) {
    return 0;
  }
  if (delay_ms <= 0) {
    job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
    return 0;
  }
  // Save the current alarm deadline so we can restore it after the delayed run.
  D->extra_double = job_timer_wakeup_time (C);
  D->extra_int2 = TLS_DELAY_ACTION_RUN;
  D->extra_int3 = 0;
  job_timer_insert (C, precise_now + 0.001 * delay_ms);
  return 0;
}

static int tls_reject_authenticated (connection_job_t C, unsigned char alert_description) {
  // HMAC-matched failures (replay/stale timestamp/internal) use direct reject path
  // and do not update reject-rate state.
  return tls_schedule_delayed_alert (C, alert_description, 0);
}

static int tls_reject_or_fallback (connection_job_t C, unsigned char alert_description) {
  // For invalid TLS transport input: reject by default, or use fallback when enabled.
  if (fallback_backend_enabled && !fallback_relay_enabled) {
    int blocked = 0;
    int delay_ms = probe_note_failure (C, 1, &blocked);
    if (blocked) {
      return tls_schedule_blocked_reject (C, alert_description);
    }
    if (delay_ms > 0) {
      return tls_schedule_delayed_alert (C, alert_description, delay_ms);
    }
    return proxy_connection_fallback (C);
  }
  int blocked = 0;
  int delay_ms = probe_note_failure (C, 1, &blocked);
  if (blocked) {
    return tls_schedule_blocked_reject (C, alert_description);
  }
  return tls_schedule_delayed_alert (C, alert_description, delay_ms);
}

static int reject_or_fallback_close (connection_job_t C) {
  // For non-TLS input on a TLS-only listener: close/reject by default,
  // with optional fallback routing when explicitly enabled.
  if (fallback_backend_enabled && !fallback_relay_enabled) {
    int blocked = 0;
    int delay_ms = probe_note_failure (C, 1, &blocked);
    if (blocked) {
      return tls_schedule_blocked_reject (C, 50 /* decode_error */);
    }
    if (delay_ms > 0) {
      return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
    }
    return proxy_connection_fallback (C);
  }
  __atomic_fetch_add (&tls_reject_non_tls, 1, __ATOMIC_RELAXED);

  // If this looks like plain HTTP, reply with a redirect instead of a silent close.
  {
    struct connection_info *c = CONN_INFO (C);
    if (!(c->flags & C_IS_TLS) && c->in.total_bytes >= 4) {
      unsigned char pfx[4];
      if (rwm_fetch_lookup (&c->in, pfx, 4) == 4) {
        if (!memcmp (pfx, "GET ", 4) ||
            !memcmp (pfx, "HEAD", 4) ||
            !memcmp (pfx, "POST", 4) ||
            !memcmp (pfx, "OPTI", 4) ||  // OPTIONS
            !memcmp (pfx, "PUT ", 4) ||
            !memcmp (pfx, "DELE", 4) ||  // DELETE
            !memcmp (pfx, "PATC", 4) ||  // PATCH
            !memcmp (pfx, "TRAC", 4) ||  // TRACE
            !memcmp (pfx, "CONN", 4) ||  // CONNECT
            !memcmp (pfx, "PRI ", 4)) {  // HTTP/2 preface
          return http_send_301_and_close (C);
        }
      }
    }
  }

  int blocked = 0;
  int delay_ms = probe_note_failure (C, 1, &blocked);
  if (blocked) {
    return tls_schedule_blocked_reject (C, 50 /* decode_error */);
  }
  return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
}

static int tls_relay_domain_or_reject (connection_job_t C, const struct domain_info *info, unsigned char alert_description) {
  if (!fallback_relay_enabled || info == NULL) {
    return tls_reject_or_fallback (C, alert_description);
  }
  int blocked = 0;
  int delay_ms = probe_note_failure (C, 1, &blocked);
  if (blocked) {
    return tls_schedule_blocked_reject (C, alert_description);
  }
  if (delay_ms > 0) {
    return tls_schedule_delayed_alert (C, alert_description, delay_ms);
  }
  return proxy_connection (C, info);
}

static int proxy_connection_fallback (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  assert (fallback_backend_enabled);
  assert (check_conn_functions (&ct_proxy_pass, 0) >= 0);

  // This connection is no longer "undetermined" once we decide to proxy it.
  undetermined_conn_leave (C);

  // Avoid obvious self-proxy loops (common footgun: 127.0.0.1:443 while listening on :443).
  if (fallback_backend_port == (int)c->our_port) {
    if ((!fallback_backend_is_ipv6 && is_ipv4_loopback (fallback_backend_target)) ||
        (fallback_backend_is_ipv6 && is_ipv6_loopback (fallback_backend_target_ipv6))) {
      vkprintf (0, "refusing to proxy to fallback-backend %s from port %d (loop risk)\n", fallback_backend_printable, c->our_port);
      fail_connection (C, -17);
      return 0;
    }
  }

  int cfd = -1;
  if (!fallback_backend_is_ipv6) {
    cfd = client_socket (fallback_backend_target.s_addr, fallback_backend_port, 0);
  } else {
    cfd = client_socket_ipv6 (fallback_backend_target_ipv6, fallback_backend_port, SM_IPV6);
  }

  if (cfd < 0) {
    kprintf ("failed to create fallback proxy pass connection to %s: %d (%m)", fallback_backend_printable, errno);
    fail_connection (C, -27);
    return 0;
  }

  c->type->crypto_free (C);
  job_incref (C);
  job_t EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C,
                                  !fallback_backend_is_ipv6 ? ntohl (fallback_backend_target.s_addr) : 0,
                                  (void *)(fallback_backend_is_ipv6 ? fallback_backend_target_ipv6 : NULL),
                                  fallback_backend_port);

  if (!EJ) {
    kprintf ("failed to create fallback proxy pass connection (2)");
    job_decref_f (C);
    fail_connection (C, -37);
    return 0;
  }

  c->type = &ct_proxy_pass;
  c->extra = job_incref (EJ);

  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return c->type->parse_execute (C);
}

static int proxy_connection (connection_job_t C, const struct domain_info *info) {
  if (fallback_backend_enabled) {
    vkprintf (2, "proxying to fallback-backend %s for connection from %s:%d\n",
              fallback_backend_printable, show_remote_ip (C), CONN_INFO(C)->remote_port);
    return proxy_connection_fallback (C);
  }

  struct connection_info *c = CONN_INFO(C);
  assert (check_conn_functions (&ct_proxy_pass, 0) >= 0);

  // This connection is no longer "undetermined" once we decide to proxy it.
  undetermined_conn_leave (C);

  const char zero[16] = {};
  if (info->target.s_addr == 0 && !memcmp (info->target_ipv6, zero, 16)) {
    vkprintf (0, "failed to proxy request to %s\n", info->domain);
    fail_connection (C, -17);
    return 0;
  }

  int port = c->our_port == 80 ? 80 : 443;

  int cfd = -1;
  if (info->target.s_addr) {
    cfd = client_socket (info->target.s_addr, port, 0);
  } else {
    cfd = client_socket_ipv6 (info->target_ipv6, port, SM_IPV6);
  }

  if (cfd < 0) {
    kprintf ("failed to create proxy pass connection: %d (%m)", errno);
    fail_connection (C, -27);
    return 0;
  }

  c->type->crypto_free (C);
  job_incref (C); 
  job_t EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C, ntohl (info->target.s_addr), (void *)info->target_ipv6, port); 

  if (!EJ) {
    kprintf ("failed to create proxy pass connection (2)");
    job_decref_f (C);
    fail_connection (C, -37);
    return 0;
  }

  c->type = &ct_proxy_pass;
  c->extra = job_incref (EJ);
      
  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return c->type->parse_execute (C);
}

int tcp_rpcs_ext_alarm (connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->in_packet_num == -3 && D->extra_int2 != TLS_DELAY_ACTION_NONE) {
    int action = D->extra_int2;
    int param = D->extra_int3;
    D->extra_int2 = TLS_DELAY_ACTION_NONE;
    D->extra_int3 = 0;
    if (action == TLS_DELAY_ACTION_ALERT) {
      return tls_send_alert_and_close (C, (unsigned char)param);
    } else if (action == TLS_DELAY_ACTION_CLOSE) {
      connection_write_close (C);
      return NEED_MORE_BYTES;
    } else if (action == TLS_DELAY_ACTION_RUN) {
      // Restore previous timeout (if any) and kick the connection to write pending bytes.
      double restore = D->extra_double;
      D->extra_double = 0;
      if (restore > precise_now) {
        job_timer_insert (C, restore);
      } else {
        // Keep no alarm (it will be removed anyway once the connection type is determined).
        job_timer_remove (C);
      }
      job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
      return 0;
    }
  }
  if (D->in_packet_num == -3) {
    __atomic_fetch_add (&tls_handshake_timeouts, 1, __ATOMIC_RELAXED);
  }
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    // Timed-out undetermined connections route to fallback only when enabled.
    if (fallback_backend_enabled) {
      int blocked = 0;
      int delay_ms = probe_note_failure (C, 1, &blocked);
      if (blocked) {
        return tls_schedule_blocked_reject (C, 50 /* decode_error */);
      }
      if (delay_ms > 0) {
        return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
      }
      return proxy_connection (C, default_domain_info);
    }

    struct connection_info *c = CONN_INFO (C);

    // If this looks like plain HTTP on :443, reply with our redirect helper.
    if (!(c->flags & C_IS_TLS) && c->in.total_bytes >= 4) {
      unsigned char pfx[4];
      if (rwm_fetch_lookup (&c->in, pfx, 4) == 4) {
        if (!memcmp (pfx, "GET ", 4) ||
            !memcmp (pfx, "HEAD", 4) ||
            !memcmp (pfx, "POST", 4) ||
            !memcmp (pfx, "OPTI", 4) ||  // OPTIONS
            !memcmp (pfx, "PUT ", 4) ||
            !memcmp (pfx, "DELE", 4) ||  // DELETE
            !memcmp (pfx, "PATC", 4) ||  // PATCH
            !memcmp (pfx, "TRAC", 4) ||  // TRACE
            !memcmp (pfx, "CONN", 4) ||  // CONNECT
            !memcmp (pfx, "PRI ", 4)) {  // HTTP/2 preface
          return http_send_301_and_close (C);
        }
      }
    }

    // If this looks like a real TLS ClientHello , fail like an HTTPS endpoint.
    if (!(c->flags & C_IS_TLS) && c->in.total_bytes >= 3) {
      unsigned char hdr3[3];
      if (rwm_fetch_lookup (&c->in, hdr3, 3) == 3) {
        if (hdr3[0] == 0x16 && hdr3[1] == 0x03 && hdr3[2] >= 0x01 && hdr3[2] <= 0x03) {
          return tls_send_alert_and_close (C, 40 /* handshake_failure */);
        }
      }
    }

    // Otherwise: just close quietly.
    connection_write_close (C);
    return NEED_MORE_BYTES;
  }
  return 0;
}

int tcp_rpcs_ext_init_accepted (connection_job_t C) {
  // Drop denied client IPs before entering the expensive handshake path.
  pthread_rwlock_rdlock (&ip_acl_lock);
  int allow_deny = ip_allowlist.set && !ip_acl_match_conn (ip_allowlist.set, C);
  int block_deny = !allow_deny && ip_blocklist.set && ip_acl_match_conn (ip_blocklist.set, C);
  pthread_rwlock_unlock (&ip_acl_lock);
  if (allow_deny) {
    __atomic_fetch_add (&tls_ip_allowlist_denied, 1, __ATOMIC_RELAXED);
    connection_write_close (C);
    return 0;
  }
  if (block_deny) {
    __atomic_fetch_add (&tls_ip_blocklist_denied, 1, __ATOMIC_RELAXED);
    connection_write_close (C);
    return 0;
  }

  // Timeout while the connection type is still undetermined (before we see enough bytes).
  // Keep it short to reduce idle accepted-connection hold time.
  job_timer_insert (C, precise_now + client_handshake_timeout);
  int r = tcp_rpcs_init_accepted_nohs (C);
  if (undetermined_conn_enter (C) < 0) {
    __atomic_fetch_add (&dos_stat_undetermined_per_ip_conns_closed, 1, __ATOMIC_RELAXED);
    connection_write_close (C);
    return 0;
  }
  int global_undetermined = __atomic_load_n (&undetermined_conn_count_global, __ATOMIC_RELAXED);
  if (undetermined_conn_count > max_undetermined_conns ||
      global_undetermined > max_undetermined_conns_global) {
    // Hard caps: too many undetermined sockets. Close immediately to keep resources bounded.
    __atomic_fetch_add (&dos_stat_undetermined_conns_closed, 1, __ATOMIC_RELAXED);
    if (global_undetermined > max_undetermined_conns_global) {
      __atomic_fetch_add (&dos_stat_undetermined_global_conns_closed, 1, __ATOMIC_RELAXED);
    }
    connection_write_close (C);
  }
  return r;
}

int tcp_rpcs_ext_close_connection (connection_job_t C, int who) {
  // Keep undetermined connection accounting correct on all close paths.
  undetermined_conn_leave (C);
  secret_conn_limit_leave (C);
  secret_ip_limit_leave (C);
  return tcp_rpcs_close_connection (C, who);
}

int tcp_rpcs_compact_parse_execute (connection_job_t C) {
#define RETURN_TLS_ERROR(info) \
  return proxy_connection (C, info);  

  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->crypto_flags & RPCF_COMPACT_OFF) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    return tcp_rpcs_parse_execute (C);
  }

  struct connection_info *c = CONN_INFO (C);
  int len;

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);

  while (1) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    if (c->flags & C_ERROR) {
      return NEED_MORE_BYTES;
    }
    if (c->flags & C_STOPPARSE) {
      return NEED_MORE_BYTES;
    }
    len = c->in.total_bytes; 
    if (len <= 0) {
      return NEED_MORE_BYTES;
    }

    if (D->in_packet_num == -3) {
      undetermined_conn_account_bytes (C, len);
      long long global_undetermined_bytes = __atomic_load_n (&undetermined_bytes_global, __ATOMIC_RELAXED);
      if (global_undetermined_bytes > max_undetermined_bytes_global) {
        vkprintf (1, "too much undetermined buffered data globally (%lld bytes), closing %s:%d\n",
                  global_undetermined_bytes, show_remote_ip (C), c->remote_port);
        __atomic_fetch_add (&dos_stat_undetermined_global_bytes_closed, 1, __ATOMIC_RELAXED);
        int blocked = 0;
        int delay_ms = probe_note_failure (C, 2, &blocked);
        if (blocked) {
          return tls_schedule_blocked_reject (C, 50 /* decode_error */);
        }
        return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
      }
    }

    if (D->in_packet_num == -3 && len > max_undetermined_buffer_bytes) {
      vkprintf (1, "too much data while undetermined (%d bytes) from %s:%d, closing\n",
                len, show_remote_ip (C), c->remote_port);
      __atomic_fetch_add (&dos_stat_undetermined_bytes_closed, 1, __ATOMIC_RELAXED);
      int blocked = 0;
      int delay_ms = probe_note_failure (C, 2, &blocked);
      if (blocked) {
        return tls_schedule_blocked_reject (C, 50 /* decode_error */);
      }
      return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
    }

    int min_len = (D->flags & RPC_F_MEDIUM) ? 4 : 1;
    if (len < min_len + 8) {
      if (D->in_packet_num == -3) {
        return NEED_MORE_BYTES;
      }
      return min_len + 8 - len;
    }

    int packet_len = 0;
    assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

    if (D->in_packet_num == -3) {
      vkprintf (1, "trying to determine type of connection from %s:%d\n", show_remote_ip (C), c->remote_port);
#if __ALLOW_UNOBFS__
      if ((packet_len & 0xff) == 0xef) {
        D->flags |= RPC_F_COMPACT;
        assert (rwm_skip_data (&c->in, 1) == 1);
        D->in_packet_num = 0;
        undetermined_conn_leave (C);
        vkprintf (1, "Short type\n");
        continue;
      } 
      if (packet_len == 0xeeeeeeee) {
        D->flags |= RPC_F_MEDIUM;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        undetermined_conn_leave (C);
        vkprintf (1, "Medium type\n");
        continue;
      }
      if (packet_len == 0xdddddddd) {
        D->flags |= RPC_F_MEDIUM | RPC_F_PAD;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        undetermined_conn_leave (C);
        vkprintf (1, "Medium type\n");
        continue;
      }
        
      // http (stats): only allow loopback to enter HTTP parser; public listeners should never switch.
      if (conn_is_loopback (C) &&
          (packet_len == *(int *)"HEAD" || packet_len == *(int *)"POST" || packet_len == *(int *)"GET " || packet_len == *(int *)"OPTI") &&
          TCP_RPCS_FUNC(C)->http_fallback_type) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "HTTP type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      // TLS-transport path
      if (c->flags & C_IS_TLS) {
        if (len < 11) {
          return NEED_MORE_BYTES;
        }

        vkprintf (1, "Established TLS connection from %s:%d\n", show_remote_ip (C), c->remote_port);
        unsigned char header[11];
        assert (rwm_fetch_lookup (&c->in, header, 11) == 11);
        if (memcmp (header, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
          vkprintf (1, "error while parsing packet: bad client dummy ChangeCipherSpec\n");
          // Reply with a TLS alert and close.
          return tls_send_alert_and_close (C, 10 /* unexpected_message */);
        }

        int tls_packet_len = 256 * header[9] + header[10];
        if (tls_packet_len < 64 || tls_packet_len > 16384) {
          vkprintf (1, "error while parsing packet: unreasonable first TLS packet length: %d\n", tls_packet_len);
          return tls_send_alert_and_close (C, 50 /* decode_error */);
        }
        min_len = 11 + tls_packet_len;
        if (len < min_len) {
          vkprintf (2, "Need %d bytes, but have only %d\n", min_len, len);
          return NEED_MORE_BYTES;
        }

        assert (rwm_skip_data (&c->in, 11) == 11);
        len -= 11;
        c->left_tls_packet_length = tls_packet_len; // store left length of current TLS packet in extra_int3
        vkprintf (2, "Receive first TLS packet of length %d\n", c->left_tls_packet_length);

        // Enable a small amount of post-handshake TCP packetization variation for this TLS connection.
        // This does not change bytes, only how they're split into TCP writes.
        if (__atomic_load_n (&c->tls_write_noise_left, __ATOMIC_RELAXED) <= 0) {
          int budget = 2048 + (lrand48_j () % 4097); // 2048..6144 bytes
          __atomic_store_n (&c->tls_write_noise_left, budget, __ATOMIC_RELAXED);
          __atomic_store_n (&c->tls_write_noise_chunk_left, 0, __ATOMIC_RELAXED);
        }

        // Add tiny timing jitter to the first few post-handshake writes (server->client).
        // This delays a couple of early encrypted records by a few milliseconds.
        if (__atomic_load_n (&c->tls_write_jitter_left, __ATOMIC_RELAXED) <= 0) {
          if ((lrand48_j () & 3) == 0) { // ~25% of connections
            __atomic_store_n (&c->tls_write_jitter_left, 1 + (lrand48_j () & 1), __ATOMIC_RELAXED); // 1..2 delays
          }
        }

        // now len >= c->left_tls_packet_length >= 64

        assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

        c->left_tls_packet_length -= 64; // skip header length
      } else if (ext_secret_cnt > 0 && allow_only_tls) {
        // TLS-transport mode: expect a TLS Handshake record (ClientHello) as the very first bytes.
        // Use explicit byte checks instead of relying on host endianness of `packet_len`.
        unsigned char header[5];
        assert (rwm_fetch_lookup (&c->in, header, 5) == 5);
        if (header[0] != 0x16 || header[1] != 0x03 || header[2] < 0x01 || header[2] > 0x03) {
          // Input is not TLS on a TLS-only listener: use non-TLS handling (HTTP redirect or close).
          return reject_or_fallback_close (C);
        }
        enum { MAX_CLIENT_HELLO_READ = 4096 };
        int client_hello_len = 256 * header[3] + header[4];
        if (client_hello_len < 64 || client_hello_len > MAX_CLIENT_HELLO_READ - 5) {
          vkprintf (1, "unreasonable ClientHello length: %d\n", client_hello_len);
          return tls_reject_or_fallback (C, 50 /* decode_error */);
        }
        min_len = 5 + client_hello_len;
        if (len < min_len) {
          return NEED_MORE_BYTES;
        }

        int read_len = len <= MAX_CLIENT_HELLO_READ ? len : MAX_CLIENT_HELLO_READ;
        unsigned char client_hello[MAX_CLIENT_HELLO_READ + 1];
        assert (rwm_fetch_lookup (&c->in, client_hello, read_len) == read_len);
        client_hello[read_len] = 0;

        const struct domain_info *info = get_sni_domain_info (client_hello, read_len);
        if (info == NULL) {
          return tls_reject_or_fallback (C, 112 /* unrecognized_name */);
        }

        vkprintf (1, "TLS type with domain %s from %s:%d\n", info->domain, show_remote_ip (C), c->remote_port);

        if (c->our_port == 80) {
          vkprintf (1, "Receive TLS request on port %d, proxying to %s\n", c->our_port, info->domain);
          RETURN_TLS_ERROR(info);
        }

        if (len > min_len) {
          vkprintf (1, "Too much data in ClientHello, receive %d instead of %d\n", len, min_len);
          return tls_reject_or_fallback (C, 50 /* decode_error */);
        }
        if (len != read_len) {
          vkprintf (1, "Too big ClientHello: receive %d bytes\n", len);
          return tls_reject_or_fallback (C, 50 /* decode_error */);
        }

        unsigned char client_random[32];
        memcpy (client_random, client_hello + 11, 32);
        memset (client_hello + 11, '\0', 32);

        unsigned char expected_random[32];
        int secret_id;
        for (secret_id = 0; secret_id < ext_secret_cnt; secret_id++) {
          if (sha256_hmac (ext_secret[secret_id], 16, client_hello, len, expected_random) < 0) {
            vkprintf (0, "sha256_hmac failed while validating ClientHello\n");
            return tls_reject_or_fallback (C, 80 /* internal_error */);
          }
          if (memcmp (expected_random, client_random, 28) == 0) {
            break;
          }
        }
        if (secret_id == ext_secret_cnt) {
          __atomic_fetch_add (&tls_handshake_fail_hmac, 1, __ATOMIC_RELAXED);
          vkprintf (1, "Receive request with unmatched client random\n");
          return tls_relay_domain_or_reject (C, info, 40 /* handshake_failure */);
        }
        int timestamp = *(int *)(expected_random + 28) ^ *(int *)(client_random + 28);
        if (!is_allowed_timestamp (timestamp)) {
          __atomic_fetch_add (&tls_handshake_fail_timestamp, 1, __ATOMIC_RELAXED);
          return tls_reject_authenticated (C, 40 /* handshake_failure */);
        }

        // Track replay only for authenticated attempts.
        if (have_client_random (client_random)) {
          __atomic_fetch_add (&tls_handshake_fail_replay, 1, __ATOMIC_RELAXED);
          vkprintf (1, "Receive again request with the same client random\n");
          return tls_reject_authenticated (C, 40 /* handshake_failure */);
        }
        if (add_client_random (client_random) < 0) {
          return tls_reject_authenticated (C, 80 /* internal_error */);
        }
        delete_old_client_randoms();
        if (secret_ip_limit_enter (C, secret_id) < 0) {
          return tls_reject_authenticated (C, 40 /* handshake_failure */);
        }
        if (secret_conn_limit_enter (C) < 0) {
          secret_ip_limit_leave (C);
          return tls_reject_authenticated (C, 40 /* handshake_failure */);
        }

        int pos = 76;
        int cipher_suites_length = read_length (client_hello, &pos);
        if (pos + cipher_suites_length > read_len) {
          vkprintf (1, "Too long cipher suites list of length %d\n", cipher_suites_length);
          return tls_reject_or_fallback (C, 50 /* decode_error */);
        }
        while (cipher_suites_length >= 2 && (client_hello[pos] & 0x0F) == 0x0A && (client_hello[pos + 1] & 0x0F) == 0x0A) {
          // skip grease
          cipher_suites_length -= 2;
          pos += 2;
        }
        if (cipher_suites_length <= 1 || client_hello[pos] != 0x13 || client_hello[pos + 1] < 0x01 || client_hello[pos + 1] > 0x03) {
          vkprintf (1, "Can't find supported cipher suite\n");
          return tls_reject_or_fallback (C, 40 /* handshake_failure */);
        }
        unsigned char cipher_suite_id = client_hello[pos + 1];
        const struct domain_profile *profile = choose_domain_profile (info);

        assert (rwm_skip_data (&c->in, len) == len);
        c->flags |= C_IS_TLS;
        __atomic_fetch_add (&tls_handshake_success, 1, __ATOMIC_RELAXED);
        c->left_tls_packet_length = -1;

        // TLS-transport clients expect exactly one ApplicationData record in the server flight.
        // Emitting multiple records here makes some clients disconnect immediately.
        // Keep a single record while preserving total encrypted-flight size.
        int records_real = get_profile_server_hello_encrypted_records (info, profile);
        int encrypted_sizes[3] = {0, 0, 0};
        int ri;
        int encrypted_wire_total = 0; // includes per-record 5-byte TLS record headers
        for (ri = 0; ri < records_real; ri++) {
          int sz = get_profile_server_hello_encrypted_size_n (info, profile, ri);
          if (sz <= 0) {
            sz = 1;
          }
          sz = jitter_profile_encrypted_size (info, profile, ri, sz);
          encrypted_sizes[ri] = sz;
          encrypted_wire_total += 5 + encrypted_sizes[ri];
        }
        // single ApplicationData record payload length; preserve total bytes on wire:
        // payload = sum(payloads) + 5*(records_real-1)
        int encrypted_payload_size = encrypted_wire_total - 5;
        if (encrypted_payload_size <= 0) {
          encrypted_payload_size = 1;
        }
        if (profile && profile->startup_payload_families_num > 0) {
          encrypted_payload_size = tcp_rpc_choose_startup_payload_size_from_families (
            profile->startup_payload_families,
            profile->startup_payload_family_weights,
            profile->startup_payload_families_num,
            encrypted_payload_size
          );
        } else {
          encrypted_payload_size = choose_tls_startup_payload_size (encrypted_payload_size);
        }

        int have_profile_tpl = profile && profile->server_hello_template && profile->server_hello_template_len > 0;
        int have_info_tpl = info->server_hello_template && info->server_hello_template_len > 0;
        int base_reversed_order = (profile && profile->is_reversed_extension_order) || (!profile && info->is_reversed_extension_order);
        unsigned int sh_variant = (unsigned int) lrand48_j () & 3u;
        // Four per-connection variants:
        // 0: prefer profile template
        // 1: prefer domain template
        // 2: synthetic (base order)
        // 3: synthetic (flipped order)
        int use_synth = 0;
        const unsigned char *selected_template = 0;
        int selected_template_len = 0;
        int selected_keyshare_offset = -1;
        int effective_reversed_order = base_reversed_order;

        if (sh_variant == 0u && have_profile_tpl) {
          selected_template = profile->server_hello_template;
          selected_template_len = profile->server_hello_template_len;
          selected_keyshare_offset = profile->server_hello_keyshare_offset;
        } else if (sh_variant == 1u && have_info_tpl) {
          selected_template = info->server_hello_template;
          selected_template_len = info->server_hello_template_len;
          selected_keyshare_offset = info->server_hello_keyshare_offset;
        } else if (sh_variant == 2u) {
          use_synth = 1;
          effective_reversed_order = base_reversed_order;
        } else if (sh_variant == 3u) {
          use_synth = 1;
          effective_reversed_order = !base_reversed_order;
        } else if (have_profile_tpl) {
          selected_template = profile->server_hello_template;
          selected_template_len = profile->server_hello_template_len;
          selected_keyshare_offset = profile->server_hello_keyshare_offset;
        } else if (have_info_tpl) {
          selected_template = info->server_hello_template;
          selected_template_len = info->server_hello_template_len;
          selected_keyshare_offset = info->server_hello_keyshare_offset;
        } else {
          use_synth = 1;
        }

        if (!selected_template && !use_synth) {
          use_synth = 1;
        }

        int response_size = 0;
        struct tcp_rpc_tls_startup_meta startup_meta;
        unsigned char *response_buffer = tcp_rpc_build_tls_startup_response (
          client_hello,
          read_len,
          client_random,
          ext_secret[secret_id],
          selected_template,
          selected_template_len,
          selected_keyshare_offset,
          use_synth,
          effective_reversed_order,
          cipher_suite_id,
          encrypted_payload_size,
          &response_size,
          &startup_meta
        );
        if (response_buffer == NULL) {
          vkprintf (0, "failed to build TLS startup response\n");
          return tls_send_alert_and_close (C, 80 /* internal_error */);
        }
        assert (startup_meta.startup_appdata_records == 1);
        assert (startup_meta.startup_shaping_plan_len == 0);

        // Keep the startup envelope byte-for-byte client compatible:
        // one ServerHello record, one dummy CCS, one startup ApplicationData record.
        struct raw_message *m = rwm_alloc_raw_message ();
        rwm_create (m, response_buffer, response_size);
        mpq_push_w (c->out_queue, m, 0);
        // Add a small delay for a subset of connections before sending the first server flight.
        // (Most connections send immediately; a minority are delayed by a few ms.)
        int jitter_ms = 0;
        unsigned int jitter_r = (unsigned int) lrand48_j ();
        if ((jitter_r & 7) < 2) { // ~25%
          jitter_ms = 1 + ((jitter_r >> 3) % 4); // 1..4ms
        }
        if (jitter_ms > 0) {
          tls_schedule_delayed_run (C, jitter_ms);
        } else {
          job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
        }

        // Startup fake-TLS shaping stays disabled. Compatibility-sensitive
        // packetization experiments belong only to post-startup bulk traffic.
        __atomic_store_n (&c->tls_write_shaping_plan_len, 0, __ATOMIC_RELAXED);
        __atomic_store_n (&c->tls_write_shaping_plan_pos, 0, __ATOMIC_RELAXED);
        __atomic_store_n (&c->tls_write_shaping_chunk_left, 0, __ATOMIC_RELAXED);
        __atomic_store_n (&c->tls_write_shaping_left, 0, __ATOMIC_RELEASE);

        free (response_buffer);
        return 11; // waiting for dummy ChangeCipherSpec and first packet
      }

      if (allow_only_tls && !(c->flags & C_IS_TLS)) {
        vkprintf (1, "Expected TLS-transport\n");
        return reject_or_fallback_close (C);
      }

#if __ALLOW_UNOBFS__
      int tmp[2];
      assert (rwm_fetch_lookup (&c->in, &tmp, 8) == 8);
      if (!tmp[1] && !(c->flags & C_IS_TLS)) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "Long type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      if (len < 64) {
        assert (!(c->flags & C_IS_TLS));
#if __ALLOW_UNOBFS__
        vkprintf (1, "random 64-byte header: first 0x%08x 0x%08x, need %d more bytes to distinguish\n", tmp[0], tmp[1], 64 - len);
#else
        vkprintf (1, "\"random\" 64-byte header: have %d bytes, need %d more bytes to distinguish\n", len, 64 - len);
#endif
        return NEED_MORE_BYTES;
      }

      unsigned char random_header[64];
      unsigned char k[48];
      assert (rwm_fetch_lookup (&c->in, random_header, 64) == 64);

      if (is_forbidden_obf2_prefix (random_header)) {
        vkprintf (1, "forbidden obfuscated2 prefix, closing\n");
        int blocked = 0;
        int delay_ms = probe_note_failure (C, 2, &blocked);
        if (blocked) {
          return tls_schedule_blocked_reject (C, 50 /* decode_error */);
        }
        return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
      }
        
      unsigned char random_header_sav[64];
      memcpy (random_header_sav, random_header, 64);
      
      struct aes_key_data key_data;
      
      int ok = 0;
      int secret_id;
      for (secret_id = 0; secret_id < 1 || secret_id < ext_secret_cnt; secret_id++) {
        if (ext_secret_cnt > 0) {
          memcpy (k, random_header + 8, 32);
          memcpy (k + 32, ext_secret[secret_id], 16);
          if (sha256 (k, 48, key_data.read_key) < 0) {
            vkprintf (0, "sha256 failed while deriving read key\n");
            connection_write_close (C);
            return NEED_MORE_BYTES;
          }
        } else {
          memcpy (key_data.read_key, random_header + 8, 32);
        }
        memcpy (key_data.read_iv, random_header + 40, 16);

        int i;
        for (i = 0; i < 32; i++) {
          key_data.write_key[i] = random_header[55 - i];
        }
        for (i = 0; i < 16; i++) {
          key_data.write_iv[i] = random_header[23 - i];
        }

        if (ext_secret_cnt > 0) {
          memcpy (k, key_data.write_key, 32);
          if (sha256 (k, 48, key_data.write_key) < 0) {
            vkprintf (0, "sha256 failed while deriving write key\n");
            connection_write_close (C);
            return NEED_MORE_BYTES;
          }
        }

        if (aes_crypto_ctr128_init (C, &key_data, sizeof (key_data)) < 0 || !c->crypto) {
          vkprintf (0, "failed to initialize obfuscated2 crypto state\n");
          connection_write_close (C);
          return NEED_MORE_BYTES;
        }
        struct aes_crypto *T = c->crypto;

        evp_crypt (T->read_aeskey, random_header, random_header, 64);
        unsigned tag = *(unsigned *)(random_header + 56);

        if (tag == 0xdddddddd || tag == 0xeeeeeeee || tag == 0xefefefef) {
          if (tag != 0xdddddddd && allow_only_tls) {
            vkprintf (1, "Expected random padding mode\n");
            return reject_or_fallback_close (C);
          }
          assert (rwm_skip_data (&c->in, 64) == 64);
          rwm_union (&c->in_u, &c->in);
          rwm_init (&c->in, 0);
          // T->read_pos = 64;
          D->in_packet_num = 0;
          undetermined_conn_leave (C);
          switch (tag) {
            case 0xeeeeeeee:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2;
              break;
            case 0xdddddddd:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2 | RPC_F_PAD;
              break;
            case 0xefefefef:
              D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE2;
              break;
          }
          assert (c->type->crypto_decrypt_input (C) >= 0);

          int target = *(short *)(random_header + 60);
          if (ext_secret_cnt > 0 && secret_ip_limit_enter (C, secret_id) < 0) {
            connection_write_close (C);
            return NEED_MORE_BYTES;
          }
          if (ext_secret_cnt > 0 && secret_conn_limit_enter (C) < 0) {
            secret_ip_limit_leave (C);
            connection_write_close (C);
            return NEED_MORE_BYTES;
          }
          D->extra_int4 = target;
          vkprintf (1, "tcp opportunistic encryption mode detected, tag = %08x, target=%d\n", tag, target);
          ok = 1;
          break;
        } else {
          aes_crypto_free (C);
          memcpy (random_header, random_header_sav, 64);
        }
      }

      if (ok) {
        continue;
      }

      if (ext_secret_cnt > 0) {
        // Close promptly on invalid 64-byte headers.
        vkprintf (1, "invalid \"random\" 64-byte header, closing\n");
        int blocked = 0;
        int delay_ms = probe_note_failure (C, 2, &blocked);
        if (blocked) {
          return tls_schedule_blocked_reject (C, 50 /* decode_error */);
        }
        return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
      }

#if __ALLOW_UNOBFS__
      vkprintf (1, "short type with 64-byte header: first 0x%08x 0x%08x\n", tmp[0], tmp[1]);
      D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE1;
      D->in_packet_num = 0;
      undetermined_conn_leave (C);

      assert (len >= 64);
      assert (rwm_skip_data (&c->in, 64) == 64);
      continue;
#else
      vkprintf (1, "invalid \"random\" 64-byte header, closing\n");
      int blocked = 0;
      int delay_ms = probe_note_failure (C, 2, &blocked);
      if (blocked) {
        return tls_schedule_blocked_reject (C, 50 /* decode_error */);
      }
      return tls_schedule_delayed_reject (C, delay_ms, 50 /* decode_error */);
#endif
    }

    int packet_len_bytes = 4;
    if (D->flags & RPC_F_MEDIUM) {
      // packet len in `medium` mode
      //if (D->crypto_flags & RPCF_QUICKACK) {
        D->flags = (D->flags & ~RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
        packet_len &= ~RPC_F_QUICKACK;
      //}
    } else {
      // packet len in `compact` mode
      if (packet_len & 0x80) {
        D->flags |= RPC_F_QUICKACK;
        packet_len &= ~0x80;
      } else {
        D->flags &= ~RPC_F_QUICKACK;
      }
      if ((packet_len & 0xff) == 0x7f) {
        packet_len = ((unsigned) packet_len >> 8);
        if (packet_len < 0x7f) {
          vkprintf (1, "error while parsing compact packet: got length %d in overlong encoding\n", packet_len);
          fail_connection (C, -1);
          return 0;
        }
      } else {
        packet_len &= 0x7f;
        packet_len_bytes = 1;
      }
      packet_len <<= 2;
    }

    if (packet_len <= 0 || (packet_len & 0xc0000000) || (!(D->flags & RPC_F_PAD) && (packet_len & 3))) {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if ((packet_len > TCP_RPCS_FUNC(C)->max_packet_len && TCP_RPCS_FUNC(C)->max_packet_len > 0))  {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if (len < packet_len + packet_len_bytes) {
      return packet_len + packet_len_bytes - len;
    }

    assert (rwm_skip_data (&c->in, packet_len_bytes) == packet_len_bytes);
    
    struct raw_message msg;
    int packet_type;

    rwm_split_head (&msg, &c->in, packet_len);
    if (D->flags & RPC_F_PAD) {
      rwm_trunc (&msg, packet_len & -4);
    }

    assert (rwm_fetch_lookup (&msg, &packet_type, 4) == 4);

    if (D->in_packet_num < 0) {
      assert (D->in_packet_num == -3);
      D->in_packet_num = 0;
      undetermined_conn_leave (C);
    }

    if (verbosity > 2) {
      kprintf ("received packet from connection %d (length %d, num %d, type %08x)\n", c->fd, packet_len, D->in_packet_num, packet_type);
      rwm_dump (&msg);
    }

    int res = -1;

    /* main case */
    c->last_response_time = precise_now;
    if (packet_type == RPC_PING) {
      res = tcp_rpcs_default_execute (C, packet_type, &msg);
    } else {
      res = TCP_RPCS_FUNC(C)->execute (C, packet_type, &msg);
    }
    if (res <= 0) {
      rwm_free (&msg);
    }

    D->in_packet_num++;
  }
  return NEED_MORE_BYTES;
#undef RETURN_TLS_ERROR
}

/*
 *
 *                END (EXTERNAL RPC SERVER)
 *
 */

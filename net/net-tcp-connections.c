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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman     
*/

#include <errno.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "common/precise-time.h"
#include "net/net-connections.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "crypto/aesni256.h"
#include "net/net-crypto-aes.h"
#include "kprintf.h"

unsigned long long tls_bulk_small_record_delays;
unsigned long long tls_bulk_small_record_flushes;
unsigned long long tls_long_flow_phase_transitions;
unsigned long long tls_long_flow_bulk_bytes_shaped;

enum {
  TLS_BULK_SMALL_RECORD_FLOOR = 256,
  TLS_BULK_SMALL_RECORD_DELAYABLE_MAX = 384
};

static int tls_can_delay_bulk_small_record (struct connection_info *c) {
  int buffered = c->out.total_bytes;
  if (!(c->flags & C_IS_TLS)) {
    return 0;
  }
  if (__atomic_load_n (&c->tls_out_records_sent, __ATOMIC_RELAXED) <= 32) {
    return 0;
  }
  if (buffered <= 0 || buffered >= TLS_BULK_SMALL_RECORD_FLOOR || buffered > TLS_BULK_SMALL_RECORD_DELAYABLE_MAX) {
    return 0;
  }
  if (c->out_p.total_bytes > 0) {
    return 0;
  }
  return 1;
}

int cpu_tcp_free_connection_buffers (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert_net_cpu_thread ();
  rwm_free (&c->in);
  rwm_free (&c->in_u);
  rwm_free (&c->out);
  rwm_free (&c->out_p);
  return 0;
}
/* }}} */


int cpu_tcp_server_writer (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();

  struct connection_info *c = CONN_INFO (C);
  
  int stop = 0;
  if (c->status == conn_write_close) {
    stop = 1;
  }
  
  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_queue, 4);
    if (!raw) { break; }
    //rwm_union (out, raw);
    c->type->write_packet (C, raw);
    rwm_free_raw_message (raw);
  }
  
  c->type->flush (C);

  if (c->type->crypto_encrypt_output && c->crypto) {
    if (tls_can_delay_bulk_small_record (c)) {
      if (!c->tls_bulk_small_record_delay_pending) {
        double delay_until = precise_now + 0.001 * (double)(1 + (lrand48_j () % 3)); // 1..3 ms
        c->tls_bulk_small_record_delay_pending = 1;
        __atomic_fetch_add (&tls_bulk_small_record_delays, 1, __ATOMIC_RELAXED);
        job_timer_insert (C, delay_until);
        return 0;
      }
      if (c->out.total_bytes < TLS_BULK_SMALL_RECORD_FLOOR &&
          job_timer_active (C) &&
          job_timer_wakeup_time (C) > precise_now) {
        return 0;
      }
      c->tls_bulk_small_record_delay_pending = 0;
      if (job_timer_active (C)) {
        job_timer_remove (C);
      }
      __atomic_fetch_add (&tls_bulk_small_record_flushes, 1, __ATOMIC_RELAXED);
    } else if (c->tls_bulk_small_record_delay_pending) {
      c->tls_bulk_small_record_delay_pending = 0;
      if (job_timer_active (C)) {
        job_timer_remove (C);
      }
      __atomic_fetch_add (&tls_bulk_small_record_flushes, 1, __ATOMIC_RELAXED);
    }
  }

  struct raw_message *raw = rwm_alloc_raw_message ();

  if (c->type->crypto_encrypt_output && c->crypto) {
    c->type->crypto_encrypt_output (C);
    *raw = c->out_p;
    rwm_init (&c->out_p, 0);
  } else {
    *raw = c->out;
    rwm_init (&c->out, 0);
  }
 
  if (raw->total_bytes && c->io_conn) {        
    mpq_push_w (SOCKET_CONN_INFO(c->io_conn)->out_packet_queue, raw, 0);
    if (stop) {
      __sync_fetch_and_or (&SOCKET_CONN_INFO(c->io_conn)->flags, C_STOPWRITE);
    }
    job_signal (JOB_REF_CREATE_PASS (c->io_conn), JS_RUN);
  } else {
    rwm_free_raw_message (raw);
  }

  return 0;
}
/* }}} */

int cpu_tcp_server_reader (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO(C);
  int bytes_received = 0;

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->in_queue, 4);
    if (!raw) { break; }
    bytes_received += raw->total_bytes;

    if (c->crypto) {
      rwm_union (&c->in_u, raw);
    } else {
      rwm_union (&c->in, raw);
    }
    rwm_free_raw_message (raw);
  }
        
  if (c->crypto) {
    assert (c->type->crypto_decrypt_input (C) >= 0);
  }

  int r = c->in.total_bytes;
        
  int s = c->skip_bytes;

  if (c->type->data_received && bytes_received > 0) {
    c->type->data_received (C, bytes_received);
  }

  if (c->flags & (C_FAILED | C_ERROR | C_NET_FAILED)) {
    return -1;
  }
  if (c->flags & C_STOPREAD) {
    return 0;
  }

  int r1 = r;

  if (s < 0) {
    // have to skip s more bytes
    if (r1 > -s) {
      r1 = -s;
    }
    rwm_skip_data (&c->in, r1);
    c->skip_bytes = s += r1;

    vkprintf (2, "skipped %d bytes, %d more to skip\n", r1, -s);
      
    if (s) {
      return 0;
    }
  }

  if (s > 0) {
    // need to read s more bytes before invoking parse_execute()
    if (r1 >= s) {
      c->skip_bytes = s = 0;
    }

    vkprintf (1, "fetched %d bytes, %d available bytes, %d more to load\n", r, r1, s ? s - r1 : 0);
    if (s) {
      return 0;
    }
  }


  while (!c->skip_bytes && !(c->flags & (C_ERROR | C_FAILED | C_NET_FAILED | C_STOPREAD)) && c->status != conn_error) {
    int bytes = c->in.total_bytes;
    if (!bytes) {
      break;
    }

    int res = c->type->parse_execute (C);
    
    // 0 - ok/done, >0 - need that much bytes, <0 - skip bytes, or NEED_MORE_BYTES
    if (!res) {
    } else if (res != NEED_MORE_BYTES) {
      bytes = (c->crypto ? c->in.total_bytes : c->in_u.total_bytes);
      // have to load or skip abs(res) bytes before invoking parse_execute
      if (res < 0) {
        res -= bytes;
      } else {
        res += bytes;
      }
      c->skip_bytes = res;
      break;
    } else {
      break;
    }
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *out = &c->out;

  int l = out->total_bytes;
  l &= ~15;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->out, &c->out_p, l, T->write_aeskey, 16) == l);
  }

  return (-out->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *in = &c->in_u;

  int l = in->total_bytes;
  l &= ~15;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->in_u, &c->in, l, T->read_aeskey, 16) == l);
  }

  return (-in->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return -c->out.total_bytes & 15;
}
/* }}} */

enum {
  TLS_LONG_FLOW_PHASE_BULK = 1,
  TLS_LONG_FLOW_PHASE_MIXED = 2,
  TLS_LONG_FLOW_PHASE_SPARSE = 3
};

static void tls_choose_long_flow_phase (struct connection_info *c) {
  unsigned int r = (unsigned int) lrand48_j ();
  int phase;
  int budget;

  if ((r & 1023) < 640) {  // ~62.5%
    phase = TLS_LONG_FLOW_PHASE_BULK;
    budget = 65536 + (int)((r >> 10) % 131073);  // 64KB..192KB
  } else if ((r & 1023) < 896) {  // ~25%
    phase = TLS_LONG_FLOW_PHASE_MIXED;
    budget = 32768 + (int)((r >> 10) % 65537);  // 32KB..96KB
  } else {  // ~12.5%
    phase = TLS_LONG_FLOW_PHASE_SPARSE;
    budget = 16384 + (int)((r >> 10) % 32769);  // 16KB..48KB
  }

  c->tls_long_flow_phase = phase;
  c->tls_long_flow_phase_bytes_left = budget;
  __atomic_fetch_add (&tls_long_flow_phase_transitions, 1, __ATOMIC_RELAXED);
}

static void tls_choose_long_flow_record_len (struct connection_info *c, int max_len, int *min_len_out, int *max_len_out) {
  int min_len = 1;
  int hi = max_len;

  if (c->tls_long_flow_phase_bytes_left <= 0 || c->tls_long_flow_phase <= 0) {
    tls_choose_long_flow_phase (c);
  }

  switch (c->tls_long_flow_phase) {
    case TLS_LONG_FLOW_PHASE_BULK:
      if (max_len >= 14336) {
        min_len = 12288;
        hi = max_len < 16384 ? max_len : 16384;
      } else if (max_len >= 8192) {
        min_len = 8192;
        hi = max_len < 14336 ? max_len : 14336;
      } else if (max_len >= 6144) {
        min_len = 4096;
        hi = max_len;
      } else {
        min_len = max_len >= 2048 ? 2048 : max_len;
        hi = max_len;
      }
      break;
    case TLS_LONG_FLOW_PHASE_MIXED:
      if (max_len >= 6144) {
        unsigned int r = (unsigned int) lrand48_j ();
        if ((r & 7) < 5) {
          min_len = 2048;
          hi = max_len < 6144 ? max_len : 6144;
        } else if ((r & 7) < 7) {
          min_len = 4096;
          hi = max_len < 8192 ? max_len : 8192;
        } else {
          min_len = 8192;
          hi = max_len < 12288 ? max_len : 12288;
        }
      } else {
        min_len = max_len >= 1400 ? 1400 : max_len;
        hi = max_len;
      }
      break;
    case TLS_LONG_FLOW_PHASE_SPARSE:
    default:
      if (max_len >= 4096) {
        unsigned int r = (unsigned int) lrand48_j ();
        if ((r & 15) < 2) {
          min_len = 3072;
          hi = max_len < 6144 ? max_len : 6144;
        } else if ((r & 15) < 10) {
          min_len = 900;
          hi = max_len < 2200 ? max_len : 2200;
        } else {
          min_len = 1400;
          hi = max_len < 4096 ? max_len : 4096;
        }
      } else {
        min_len = max_len >= 900 ? 900 : max_len;
        hi = max_len;
      }
      break;
  }

  if (max_len >= TLS_BULK_SMALL_RECORD_FLOOR && min_len < TLS_BULK_SMALL_RECORD_FLOOR) {
    min_len = TLS_BULK_SMALL_RECORD_FLOOR;
  }
  if (min_len < 1) { min_len = 1; }
  if (hi < min_len) { hi = min_len; }
  *min_len_out = min_len;
  *max_len_out = hi;
}

int cpu_tcp_aes_crypto_ctr128_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);

  while (c->out.total_bytes) {
    int len = c->out.total_bytes;
    if (c->flags & C_IS_TLS) {
      assert (c->left_tls_packet_length >= 0);
      // Keep record sizes variable for the whole connection.
      //
      // Cap sizes at the maximum TLS record fragment size (16KB) to keep buffering bounded;
      // TCP packetization shaping is handled elsewhere (socket writer shaping).
      const int TLS_MAX_RECORD = 16384;
      const int EARLY_RECORDS = 32;

      int max_len = len;
      int min_len = 1;

      int records_sent = __atomic_load_n (&c->tls_out_records_sent, __ATOMIC_RELAXED);
      if (records_sent < EARLY_RECORDS) {
        // Early after handshake: allow a wider range (including smaller records),
        // but avoid pathological 1-byte records when we have enough buffered data.
        if (max_len > TLS_MAX_RECORD) { max_len = TLS_MAX_RECORD; }
        min_len = (max_len >= 256) ? 256 : max_len;
      } else {
        // Steady state: keep each connection in a sizing phase for a while so
        // long transfers look bursty rather than sampled from a fixed histogram.
        if (max_len > TLS_MAX_RECORD) { max_len = TLS_MAX_RECORD; }
        tls_choose_long_flow_record_len (c, max_len, &min_len, &max_len);
      }

      if (min_len < 1) { min_len = 1; }
      if (max_len < min_len) { max_len = min_len; }

      len = max_len;
      if (max_len > min_len) {
        unsigned int rlen = (unsigned int) lrand48_j ();
        len = min_len + (int)(rlen % (unsigned int)(max_len - min_len + 1));
      }

      if (records_sent >= EARLY_RECORDS && c->tls_long_flow_phase_bytes_left > 0) {
        c->tls_long_flow_phase_bytes_left -= len;
        __atomic_fetch_add (&tls_long_flow_bulk_bytes_shaped, (unsigned long long)len, __ATOMIC_RELAXED);
      }

      unsigned char *hdr = rwm_postpone_alloc (&c->out_p, 5);
      if (hdr) {
        hdr[0] = 0x17;
        hdr[1] = 0x03;
        hdr[2] = 0x03;
        hdr[3] = (unsigned char)(len >> 8);
        hdr[4] = (unsigned char)(len & 255);
      } else {
        unsigned char header[5] = {0x17, 0x03, 0x03, (unsigned char)(len >> 8), (unsigned char)(len & 255)};
        rwm_push_data (&c->out_p, header, 5);
      }
      records_sent = __atomic_add_fetch (&c->tls_out_records_sent, 1, __ATOMIC_RELAXED);
      vkprintf (2, "Send TLS-packet of length %d (records_sent=%d)\n", len, records_sent);
    }

    assert (rwm_encrypt_decrypt_to (&c->out, &c->out_p, len, T->write_aeskey, 1) == len);
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  const int TLS_DECRYPT_CHUNK_MAX = 16384;

  while (c->in_u.total_bytes) {
    int len = c->in_u.total_bytes;
    if (c->flags & C_IS_TLS) {
      assert (c->left_tls_packet_length >= 0);
      if (c->left_tls_packet_length == 0) {
        if (len < 5) {
          vkprintf (2, "Need %d more bytes to parse TLS header\n", 5 - len);
          return 5 - len;
        }

        unsigned char header[5];
        assert (rwm_fetch_lookup (&c->in_u, header, 5) == 5);
        if (memcmp (header, "\x17\x03\x03", 3) != 0) {
          vkprintf (1, "error while parsing packet: expect TLS header\n");
          fail_connection (C, -1);
          return 0;
        }
        c->left_tls_packet_length = 256 * header[3] + header[4];
        vkprintf (2, "Receive TLS-packet of length %d\n", c->left_tls_packet_length);
        assert (rwm_skip_data (&c->in_u, 5) == 5);
        len -= 5;
      }

      if (c->left_tls_packet_length < len) {
        len = c->left_tls_packet_length;
      }
      if (len > TLS_DECRYPT_CHUNK_MAX) {
        len = TLS_DECRYPT_CHUNK_MAX;
      }
      c->left_tls_packet_length -= len;
    }
    vkprintf (2, "Read %d bytes out of %d available\n", len, c->in_u.total_bytes);
    assert (rwm_encrypt_decrypt_to (&c->in_u, &c->in, len, T->read_aeskey, 1) == len);
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return 0;
}
/* }}} */

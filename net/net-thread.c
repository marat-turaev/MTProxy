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

    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman     
    
*/
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "net/net-thread.h"
#include "net/net-connections.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-server.h"

#include "common/mp-queue.h"
#include "common/kprintf.h"
#include "common/server-functions.h"
#include "common/common-stats.h"

#define NEV_TCP_CONN_READY 1
#define NEV_TCP_CONN_CLOSE 2
#define NEV_TCP_CONN_ALARM 3
#define NEV_TCP_CONN_WAKEUP 4

struct notification_event {
  int type;
  void *who;
};

/*
 * notification_event is a tiny, high-frequency allocation under load.
 * Pool it and avoid per-event job_signal() to reduce allocator churn and wakeups.
 */
#define NEV_POOL_MAX 65536
static struct mp_queue *nev_pool;
static volatile int nev_pool_inited;
static volatile int nev_pool_size;
static volatile long long nev_pool_trim_freed;

static volatile long long nev_tls_hits;
static volatile long long nev_tls_misses;
static volatile long long nev_pool_hits;
static volatile long long nev_pool_misses;
static volatile long long nev_malloc;
static volatile long long nev_free;
static volatile long long nev_pool_push;
static volatile long long nev_pool_drop;

#define NEV_TLS_MAX 256
static __thread struct notification_event *nev_tls_head;
static __thread int nev_tls_cnt;

static void nev_pool_init (void) {
  if (nev_pool) {
    return;
  }
  if (__sync_bool_compare_and_swap (&nev_pool_inited, 0, 1)) {
    nev_pool = alloc_mp_queue_w ();
    __sync_synchronize ();
  } else {
    while (!nev_pool) {
      __sync_synchronize ();
    }
  }
}

static struct notification_event *notification_event_alloc (void) {
  if (nev_tls_head) {
    struct notification_event *ev = nev_tls_head;
    nev_tls_head = (struct notification_event *)ev->who;
    nev_tls_cnt--;
    __sync_fetch_and_add (&nev_tls_hits, 1);
    memset (ev, 0, sizeof (*ev));
    return ev;
  }
  __sync_fetch_and_add (&nev_tls_misses, 1);
  if (!nev_pool) {
    nev_pool_init ();
  }
  struct notification_event *ev = nev_pool ? mpq_pop_nw (nev_pool, 4) : NULL;
  if (ev) {
    __sync_fetch_and_add (&nev_pool_size, -1);
    __sync_fetch_and_add (&nev_pool_hits, 1);
  } else {
    ev = malloc (sizeof (*ev));
    assert (ev);
    __sync_fetch_and_add (&nev_pool_misses, 1);
    __sync_fetch_and_add (&nev_malloc, 1);
  }
  memset (ev, 0, sizeof (*ev));
  return ev;
}

static void notification_event_free (struct notification_event *ev) {
  if (!ev) {
    return;
  }
  if (nev_tls_cnt < NEV_TLS_MAX) {
    ev->who = nev_tls_head;
    nev_tls_head = ev;
    nev_tls_cnt++;
    return;
  }
  if (!nev_pool) {
    nev_pool_init ();
  }
  if (!nev_pool) {
    free (ev);
    __sync_fetch_and_add (&nev_free, 1);
    return;
  }
  int sz = __sync_add_and_fetch (&nev_pool_size, 1);
  if (sz <= NEV_POOL_MAX) {
    mpq_push_w (nev_pool, ev, 0);
    __sync_fetch_and_add (&nev_pool_push, 1);
  } else {
    __sync_fetch_and_add (&nev_pool_size, -1);
    free (ev);
    __sync_fetch_and_add (&nev_pool_drop, 1);
    __sync_fetch_and_add (&nev_free, 1);
  }
}

int notification_event_prepare_stat (stats_buffer_t *sb) {
  sb_printf (sb, ">>>>>>notification_event>>>>>>\tstart\n");
  sb_printf (sb, "nev_tls_hits\t%lld\n", (long long) nev_tls_hits);
  sb_printf (sb, "nev_tls_misses\t%lld\n", (long long) nev_tls_misses);
  sb_printf (sb, "nev_pool_hits\t%lld\n", (long long) nev_pool_hits);
  sb_printf (sb, "nev_pool_misses\t%lld\n", (long long) nev_pool_misses);
  sb_printf (sb, "nev_malloc\t%lld\n", (long long) nev_malloc);
  sb_printf (sb, "nev_free\t%lld\n", (long long) nev_free);
  sb_printf (sb, "nev_pool_push\t%lld\n", (long long) nev_pool_push);
  sb_printf (sb, "nev_pool_drop\t%lld\n", (long long) nev_pool_drop);
  sb_printf (sb, "nev_pool_size\t%d\n", (int) nev_pool_size);
  sb_printf (sb, "nev_pool_trim_freed\t%lld\n", (long long) nev_pool_trim_freed);
  sb_printf (sb, "<<<<<<notification_event<<<<<<\tend\n");
  return sb->pos;
}

#define NEV_POOL_TRIM_TARGET (NEV_POOL_MAX / 4)
void notification_event_pool_trim (void) {
  if (!nev_pool) {
    return;
  }
  while (__atomic_load_n (&nev_pool_size, __ATOMIC_RELAXED) > NEV_POOL_TRIM_TARGET) {
    struct notification_event *ev = mpq_pop_nw (nev_pool, 4);
    if (!ev) { break; }
    __sync_fetch_and_add (&nev_pool_size, -1);
    __sync_fetch_and_add (&nev_pool_trim_freed, 1);
    free (ev);
  }
}

void run_notification_event (struct notification_event *ev) {
  connection_job_t C = ev->who;
  switch (ev->type) {
  case NEV_TCP_CONN_READY:
    if (TCP_RPCC_FUNC(C)->rpc_ready && TCP_RPCC_FUNC(C)->rpc_ready (C) < 0) {
      fail_connection (C, -8);
    }
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_CLOSE:
    TCP_RPCC_FUNC(C)->rpc_close (C, 0);
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_ALARM:
    TCP_RPCC_FUNC(C)->rpc_alarm (C);
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_WAKEUP:
    TCP_RPCC_FUNC(C)->rpc_wakeup (C);
    job_decref (JOB_REF_PASS (C));
    break;
  default:
    assert (0);
  }
  notification_event_free (ev);
}

struct notification_event_job_extra {
  struct mp_queue *queue;
  volatile int pending; // 1 while job is scheduled/running, 0 when idle
};
static job_t notification_job;

int notification_event_run (job_t job, int op, struct job_thread *JT) {   
  if (op != JS_RUN) {
    return JOB_ERROR;
  }
  struct notification_event_job_extra *E = (void *)job->j_custom;

  while (1) {
    struct notification_event *ev;
    while ((ev = mpq_pop_nw (E->queue, 4)) != 0) {
      run_notification_event (ev);
    }

    // Mark idle; then do one extra non-blocking pop to avoid a missed wakeup
    // if an event was enqueued between the last pop and this store.
    __atomic_store_n (&E->pending, 0, __ATOMIC_RELEASE);
    ev = mpq_pop_nw (E->queue, 4);
    if (!ev) {
      break;
    }
    __atomic_store_n (&E->pending, 1, __ATOMIC_RELAXED);
    run_notification_event (ev);
  }

  return 0;
}

void notification_event_job_create (void) {
  notification_job = create_async_job (notification_event_run, JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_FINISH), 0, sizeof (struct notification_event_job_extra), 0, JOB_REF_NULL);

  struct notification_event_job_extra *E = (void *)notification_job->j_custom;
  E->queue = alloc_mp_queue_w ();
  E->pending = 0;
  
  unlock_job (JOB_REF_CREATE_PASS (notification_job));
}

void notification_event_insert_conn (connection_job_t C, int type) {
  struct notification_event *ev = notification_event_alloc ();
  ev->who = job_incref (C);
  ev->type = type;

  struct notification_event_job_extra *E = (void *)notification_job->j_custom;
  mpq_push_w (E->queue, ev, 0);
  if (__sync_bool_compare_and_swap (&E->pending, 0, 1)) {
  job_signal (JOB_REF_CREATE_PASS (notification_job), JS_RUN);
}
}

void notification_event_insert_tcp_conn_close (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_CLOSE);
}

void notification_event_insert_tcp_conn_ready (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_READY);
}

void notification_event_insert_tcp_conn_alarm (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_ALARM);
}

void notification_event_insert_tcp_conn_wakeup (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_WAKEUP);
}

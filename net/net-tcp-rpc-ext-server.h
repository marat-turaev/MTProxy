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

    Copyright 2016-2018 Telegram Messenger Inc                 
              2016-2018 Nikolai Durov
*/

#pragma once

#define __ALLOW_UNOBFS__ 0

#include "net/net-tcp-rpc-server.h"
#include "net/net-connections.h"

typedef struct stats_buffer stats_buffer_t;

extern conn_type_t ct_tcp_rpc_ext_server;

int tcp_rpcs_compact_parse_execute (connection_job_t c);

// Adds an MTProto secret.
// Returns 0 on success, 1 if duplicate, -1 if capacity is exhausted.
int tcp_rpcs_set_ext_secret(unsigned char secret[16]);

void tcp_rpc_add_proxy_domain (const char *domain);

void tcp_rpc_init_proxy_domains();

// When set, non-MTProxy TLS connections are proxied (TCP passthrough) to this backend,
// instead of proxying to the requested SNI domain. Format: "host:port" or "[ipv6]:port".
// Returns 0 on success, <0 on error.
int tcp_rpc_set_fallback_backend (const char *backend);
int tcp_rpc_fallback_backend_enabled (void);
int tcp_rpc_set_ip_blocklist_file (const char *filename);
int tcp_rpc_set_ip_allowlist_file (const char *filename);
void tcp_rpc_set_ip_acl_refresh_interval (int seconds);
void tcp_rpc_refresh_ip_acl (void);
void tcp_rpc_set_secret_max_unique_ips (int limit);
void tcp_rpc_set_secret_max_connections (int limit);
void tcp_rpc_set_secret_max_total_octets (unsigned long long limit);
void tcp_rpc_set_client_handshake_timeout (int timeout_seconds);
void tcp_rpc_set_replay_cache_max_entries (int limit);
void tcp_rpc_set_replay_cache_max_age (int seconds);
void tcp_rpc_set_replay_cache_max_bytes (unsigned long long bytes_limit);
void tcp_rpc_secret_note_data_received (connection_job_t C, int bytes_received);
void tcp_rpc_secret_note_data_sent (connection_job_t C, int bytes_sent);

// Exposes TLS-transport domain sizing results and fallback config via /stats.
int tcp_rpc_proxy_domains_prepare_stat (stats_buffer_t *sb);

// Periodic replay cache maintenance for TLS transport mode.
void tcp_rpc_ext_replay_cache_cleanup (void);

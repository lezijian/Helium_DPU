/*
 * ha_sync.h - ha_sync plugin header
 */
#ifndef __included_ha_sync_h__
#define __included_ha_sync_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/lock.h>
#include <vppinfra/atomics.h>
#include <vppinfra/fifo.h>
#include <vnet/ip/format.h>

#define HA_SYNC_UDP_PORT 10311
#define HA_SYNC_MAX_TX_PAYLOAD 1400
#define HA_SYNC_MTU 1500
#define HA_SYNC_HEARTBEAT_INTERVAL_SEC 5
#define HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS 3
#define HA_SYNC_DEFAULT_DOMAIN_ID 0
#define HA_SYNC_DEFAULT_POOL_SIZE 2048
#define HA_SYNC_MAGIC 0xAF25EE00



typedef enum
{
    HA_SYNC_MSG_REQUEST = 0,
    HA_SYNC_MSG_RESPONSE = 1,
    HA_SYNC_MSG_HELLO = 2,
    HA_SYNC_MSG_HEARTBEAT = 3,
} ha_sync_msg_type_t;

typedef enum
{
    HA_SYNC_APP_LB = 23,
    HA_SYNC_APP_SPI = 25,
    HA_SYNC_APP_NAT = 33,
    HA_SYNC_APP_MAP_CE = 35,
    HA_SYNC_APP_ACL_REFLECT = 37,
} ha_sync_app_type_t;


typedef int (*ha_sync_snapshot_send_cb_t) (u32 app_type, void *ctx);
typedef void (*ha_sync_session_apply_cb_t) (u32 app_type, void *ctx, u8 *session, u16 session_len);

typedef struct __attribute__ ((packed))
{
    u32 magic;              // magic number 0xAF25EE00
    ip4_address_t src_ip;   // source ip address
    u8 domain;              // domain id
    u8 msg_type;            // message type
    u16 length;             // packet length
    u32 seq_number;         // sequence number
    u8 count;               // message count
    u8 reserve[7];          // reserve bytes
} ha_sync_packet_header_t;

typedef struct __attribute__ ((packed))
{ 
    u16 session_length;     // session length
    u8 app_type;            // application type
} ha_sync_session_header_t;

typedef struct 
{
    u8 app_type;
    void *context;
    ha_sync_snapshot_send_cb_t snapshot_send_cb;
    ha_sync_session_apply_cb_t session_apply_cb;
} ha_sync_session_registration_t;


typedef struct 
{
    u8 msg_type;            // message type
    u8 session_count;       // session count
    u16 length;             // payload length
    u32 seq_number;         // sequence number
    u8 *payload;
} ha_sync_tx_packet_t;

typedef struct 
{
    u8 msg_type;
    u32 seq_number;
} ha_sync_fast_msg_t;   // 快速消息，不包含payload，不需要重传，主要是 response 和 heartbeat


typedef struct 
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
    u8 *data;
    u32 session_count;
    u32 *pending_fifo;      // 待发送的sequence number队列
    f64 last_flush_time;
    ha_sync_fast_msg_t *fast_msg_queue;
} ha_sync_per_thread_buffer_t;


typedef struct
{
    u32 fib_index;
    ip4_address_t src;
    ip4_address_t dst;
    u16 src_port;
    u16 dst_port;
    u16 payload_len;
    u8 payload[HA_SYNC_MAX_TX_PAYLOAD];
} ha_sync_tx_request_t;

typedef struct
{
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    u8 enabled;
    u32 fib_index;
    ip4_address_t src_address;
    u16 src_port;
    u16 dst_port;
    u32 domain_id;
    u16 packet_size;
    ip4_address_t peer_address;
    u8 peer_is_set;

    f64 heartbeat_interval_sec;
    u32 heartbeat_max_fail_counts;
    u32 global_seq_number;

    ha_sync_tx_packet_t *ha_sync_tx_pool;
    uword *seq_to_pool_index;
    clib_spinlock_t tx_lock; 
    
    ha_sync_session_registration_t *registrations;
    u32 num_registrations;

    ha_sync_per_thread_buffer_t *per_thread_buffers;

} ha_sync_main_t;

extern ha_sync_main_t ha_sync_main;

extern vlib_node_registration_t ha_sync_process_node;
extern vlib_node_registration_t ha_sync_input_worker_node;
extern vlib_node_registration_t ha_sync_output_worker_node;
extern vlib_node_registration_t ha_sync_snapshot_node;

void ha_sync_per_thread_buffer_add (u32 thread_index, u8 app_type, u8 *session_data, u16 data_len);
void ha_sync_per_thread_buffer_flush (u32 thread_index);

u32 ha_sync_tx_pool_add (u32 seq, u8 msg_type, u8 session_count, u8 *payload, u16 payload_len);
int ha_sync_tx_pool_get_by_seq (u32 seq, ha_sync_tx_packet_t *out_data);
void ha_sync_tx_pool_del_by_seq (u32 seq);
void ha_sync_pool_reset_and_clear ();
void ha_sync_tx_pool_free ();
void ha_sync_release_resources ();

int ha_sync_register_session_application (ha_sync_session_registration_t *reg);
int ha_sync_unregister_session_application (u32 app_type);
void ha_sync_send_response (u32 seq_number, u32 thread_index);
void ha_sync_send_hello (u32 thread_index);


#endif 

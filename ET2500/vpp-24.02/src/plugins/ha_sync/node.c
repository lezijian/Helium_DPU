/*
 * node.c - ha_sync graph nodes
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>

#include <ha_sync/ha_sync.h>

typedef struct
{
  u8 is_ha;
  u8 msg_type;
  u8 domain;
  u16 session_count;
  u32 seq_number;
  u32 magic;
  u32 src_ip;
} ha_sync_input_trace_t;

typedef struct
{
  ip4_address_t dst;
  u32 seq_number;
  u16 dst_port;
  u16 payload_len;
  u8 msg_type;
} ha_sync_output_trace_t;

static int
ha_sync_peer_find (ha_sync_main_t *hsm, const ip4_address_t *ip4)
{
  if (!hsm->peer_is_set)
    return -1;
  return hsm->peer_address.as_u32 == ip4->as_u32 ? 0 : -1;
}

static_always_inline ha_sync_session_registration_t *
ha_sync_get_registration (u32 app_type)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_session_registration_t *reg = NULL;

  vec_foreach (reg, hsm->registrations)
  {
    if (reg->app_type == app_type)
      return reg;
  }

  clib_warning ("No registration for app type %d", app_type);
  return NULL;

}

static_always_inline void
ha_sync_prepare_udp_header (vlib_buffer_t *b, u16 payload_len,
                            const ip4_address_t *dst)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  u16 total_len = sizeof (ip4_header_t) + sizeof (udp_header_t) + payload_len;
  vlib_buffer_advance (b, -(word)(sizeof(ip4_header_t) + sizeof(udp_header_t)));
  b->current_length = total_len;
  
  ip4_header_t *ip = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *)(ip + 1);

  // 1. 构造 UDP 头部
  udp->src_port = clib_host_to_net_u16 (hsm->src_port);
  udp->dst_port = clib_host_to_net_u16 (hsm->dst_port);
  udp->length = clib_host_to_net_u16 (payload_len + sizeof(udp_header_t));
  udp->checksum = 0;

  // 2. 构造 IP 头部
  ip->ip_version_and_header_length = 0x45; // IP 版本 4，头部长度 5 * 4 = 20 字节
  ip->tos = 0; // Type of Service，默认值 0
  ip->length = clib_host_to_net_u16 (total_len);
  ip->fragment_id = 0; // 分片 ID，默认值 0
  ip->flags_and_fragment_offset = 0; // 标志位和分片偏移，默认值 0
  ip->ttl = 255; // Time to Live，默认值 255
  ip->protocol = IP_PROTOCOL_UDP; // 协议号 17
  ip->src_address = hsm->src_address;
  ip->dst_address = *dst;
  ip->checksum = ip4_header_checksum (ip);
}


#ifndef CLIB_MARCH_VARIANT
static u8 *
format_ha_sync_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ha_sync_input_trace_t *t = va_arg (*args, ha_sync_input_trace_t *);

  s = format (s, "ha-sync-input: %s", 
              t->is_ha ? "MATCHED" : "SKIPPED (Not HA)");

  if (t->is_ha)
  {
    s = format (s, "\n    magic: 0x%08x, seq: %u, type: %u, domain: %u",
                t->magic, t->seq_number, t->msg_type, t->domain);
    
    s = format (s, "\n    src-ip: %U, sessions: %u",
                format_ip4_address, &t->src_ip,
                t->session_count);
  }
  return s;
}

static u8 *
format_ha_sync_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ha_sync_output_trace_t *t = va_arg (*args, ha_sync_output_trace_t *);

  s = format (s, "ha-sync-output: [Type %u] -> %U:%d",
              t->msg_type,
              format_ip4_address, &t->dst,
              t->dst_port);

  s = format (s, "\n    seq: %u, payload-len: %u",
              t->seq_number, 
              t->payload_len);

  char *type_str = "UNKNOWN";
  if (t->msg_type == HA_SYNC_MSG_RESPONSE) type_str = "RESPONSE";
  else if (t->msg_type == HA_SYNC_MSG_REQUEST) type_str = "REQUEST";
  else if (t->msg_type == HA_SYNC_MSG_HEARTBEAT) type_str = "HEARTBEAT";
  else if (t->msg_type == HA_SYNC_MSG_HELLO) type_str = "HELLO";
  
  s = format (s, " [%s]", type_str);
  return s;
}
#endif

#define foreach_ha_sync_input_error \
  _(RX, "input packets received")    \
  _(MATCH, "udp/10311 packets matched") \
  _(REQUEST, "ha_sync request packets received") \
  _(RESPONSE, "ha_sync response packets received") \
  _(HELLO, "ha_sync hello packets received") \
  _(HEARTBEAT, "ha_sync heartbeat packets received")

typedef enum
{
#define _(sym, str) HA_SYNC_INPUT_ERROR_##sym,
  foreach_ha_sync_input_error
#undef _
    HA_SYNC_INPUT_N_ERROR,
} ha_sync_input_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ha_sync_input_error_strings[] = {
#define _(sym, str) str,
  foreach_ha_sync_input_error
#undef _
};
#endif

typedef enum
{
  HA_SYNC_INPUT_NEXT_DROP,
  HA_SYNC_INPUT_N_NEXT,
} ha_sync_input_next_t;

static_always_inline u8
ha_sync_is_udp_10311 (vlib_buffer_t *b)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  udp_header_t *udp;

  if (PREDICT_FALSE (ip4->protocol != IP_PROTOCOL_UDP))
    return 0;

  udp = ip4_next_header (ip4);
  return clib_net_to_host_u16 (udp->dst_port) == HA_SYNC_UDP_PORT;
}

#define foreach_ha_sync_output_error \
  _(TX, "output packets sent")     \
  _(NO_BUFFER, "buffer allocation failed") \
  _(POOL_MISS, "tx pool sequence not found") \
  _(NO_PEER, "peer address not configured") \
  _(TX_REQUEST, "ha_sync request packets sent") \
  _(TX_RESPONSE, "ha_sync response packets sent") \
  _(TX_HELLO, "ha_sync hello packets sent") \
  _(TX_HEARTBEAT, "ha_sync heartbeat packets sent")

typedef enum
{
#define _(sym, str) HA_SYNC_OUTPUT_ERROR_##sym,
  foreach_ha_sync_output_error
#undef _
    HA_SYNC_OUTPUT_N_ERROR,
} ha_sync_output_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ha_sync_output_error_strings[] = {
#define _(sym, str) str,
  foreach_ha_sync_output_error
#undef _
};
#endif

VLIB_NODE_FN (ha_sync_input_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next;
  u32 next_index = node->cached_next_index;
  u32 n_match = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      ha_sync_packet_header_t *h0;
      u32 next0;
      u8 is_ha_packet = 0;
      
      bi0 = to_next[0] = from[0];
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      vnet_feature_next (&next0, b0);

      if (hsm->enabled && ha_sync_is_udp_10311 (b0))
      {
        ip0 = vlib_buffer_get_current (b0);
        udp0 = ip4_next_header (ip0);
        u32 udp_len = clib_net_to_host_u16 (udp0->length);

        if (udp_len >= (sizeof(udp_header_t) + sizeof(ha_sync_packet_header_t)))
        {
          h0 = (ha_sync_packet_header_t *) (udp0 + 1);
          u16 total_payload_len = clib_net_to_host_u16 (h0->length);
          if (PREDICT_FALSE (total_payload_len >
                             udp_len - sizeof (udp_header_t) -
                               sizeof (ha_sync_packet_header_t)))
            goto trace_and_next;

          if (clib_net_to_host_u32 (h0->magic) == HA_SYNC_MAGIC &&
                ha_sync_peer_find (hsm, &h0->src_ip) >= 0 &&
                h0->domain == hsm->domain_id)
          {
            is_ha_packet = 1;
            n_match++;
            
            // 匹配成功，终结此报文
            next0 = HA_SYNC_INPUT_NEXT_DROP;
              
            u8 msg_type = h0->msg_type;
            switch (msg_type)
            {
              case HA_SYNC_MSG_REQUEST: 
              {
                u8 session_count = h0->count;
                u8 *packet_end = (u8 *)h0 + sizeof(ha_sync_packet_header_t) + total_payload_len;
                ha_sync_session_header_t *session_hdr = (ha_sync_session_header_t *)((h0 + 1));
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_REQUEST, 1);
                
                for (int i = 0; i < session_count; i++)
                {
                  // check session header boundary
                  if (PREDICT_FALSE((u8 *)session_hdr + sizeof(ha_sync_session_header_t) > packet_end))
                  {
                    clib_warning("HA_SYNC_MSG_REQUEST: Session header exceeds packet boundary");
                    break;
                  }

                  u16 session_data_len = clib_net_to_host_u16 (session_hdr->session_length);
                  u8 app_type = session_hdr->app_type;
                  u8 *session_data = (u8 *)(session_hdr + 1);
                  
                  if (PREDICT_FALSE(session_data + session_data_len > packet_end))
                  {
                    clib_warning("HA_SYNC_MSG_REQUEST: Session data exceeds packet boundary");
                    break;
                  }

                  ha_sync_session_registration_t *reg = ha_sync_get_registration (app_type);
                  if (PREDICT_FALSE(reg != NULL && reg->session_apply_cb != NULL))
                  {
                    reg->session_apply_cb((u32)app_type, reg->context, session_data, session_data_len);
                  }

                  session_hdr = (ha_sync_session_header_t *)(session_data + session_data_len);
                  if ((u8 *)session_hdr >= packet_end)
                    break;
                }
                break;
              }
              case HA_SYNC_MSG_RESPONSE:
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_RESPONSE, 1);
                break;

              case HA_SYNC_MSG_HELLO:
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_HELLO, 1);
                break;

              case HA_SYNC_MSG_HEARTBEAT:
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_HEARTBEAT, 1);
                break;

              default:
                next0 = HA_SYNC_INPUT_NEXT_DROP;
            }
          }
        }
      }
trace_and_next:
      // trace
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                          (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        ha_sync_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
        t->is_ha = is_ha_packet;
        if (is_ha_packet)
        {
          t->msg_type = h0->msg_type;
          t->domain = h0->domain;
          t->session_count = h0->count;
          t->seq_number = clib_net_to_host_u32 (h0->seq_number);
          t->magic = clib_net_to_host_u32 (h0->magic);
          t->src_ip = h0->src_ip.as_u32;
        }
        else
        {
          t->msg_type = 0;
        }
      }
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  // 更新计数器
  vlib_node_increment_counter (vm, node->node_index, HA_SYNC_INPUT_ERROR_RX, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, HA_SYNC_INPUT_ERROR_MATCH, n_match);
  return frame->n_vectors;
}

VLIB_NODE_FN (ha_sync_output_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 thread_index = vm->thread_index;
  ha_sync_per_thread_buffer_t *ptb;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;

  if (!hsm->enabled)
    return 0;

  if (!hsm->peer_is_set)
  {
    vlib_node_increment_counter (vm, node->node_index,
                                  HA_SYNC_OUTPUT_ERROR_NO_PEER, 1);
    return 0;
  }

  if (thread_index >= vec_len (hsm->per_thread_buffers))
    return 0;
  ptb = &hsm->per_thread_buffers[thread_index];
  
  // 1. 统计两个队列待处理的总量
  u32 n_fast = clib_fifo_elts (ptb->fast_msg_queue);
  u32 n_pending = clib_fifo_elts (ptb->pending_fifo);
  u32 n_total = n_fast + n_pending;

  if (n_total == 0)
    return 0;

  if (n_total > VLIB_FRAME_SIZE)
  {
    n_total = VLIB_FRAME_SIZE;
  }

  // 申请 buffer index
  u32 bi[VLIB_FRAME_SIZE];
  u32 n_alloc = vlib_buffer_alloc (vm, bi, n_total);
  if (PREDICT_FALSE (n_alloc == 0))
  {
    vlib_node_increment_counter (vm, node->node_index,
                                  HA_SYNC_OUTPUT_ERROR_NO_BUFFER, n_total);
    return 0;
  }
  
  u32 bi_to_send[VLIB_FRAME_SIZE];
  u32 sent = 0;
  u32 b_idx = 0;

  while (b_idx < n_alloc && clib_fifo_elts (ptb->fast_msg_queue) > 0)
  {
    ha_sync_fast_msg_t fmsg;
    clib_fifo_sub1 (ptb->fast_msg_queue, fmsg);
    vlib_buffer_t *b = vlib_get_buffer (vm, bi[b_idx]);

    ha_sync_packet_header_t *h = vlib_buffer_get_current (b);
    h->magic = clib_host_to_net_u32 (HA_SYNC_MAGIC);
    h->src_ip = hsm->src_address;
    h->domain = hsm->domain_id;
    h->msg_type = fmsg.msg_type;
    h->length = 0;
    h->seq_number = clib_host_to_net_u32 (fmsg.seq_number);
    h->count = 0;
    memset (h->reserve, 0, sizeof (h->reserve));

    b->current_length = sizeof (ha_sync_packet_header_t);
    // 封装UDP/IP
    ha_sync_prepare_udp_header (b, b->current_length, &hsm->peer_address);
    vnet_buffer (b)->sw_if_index[VLIB_TX] = hsm->fib_index;

    bi_to_send[sent++] = bi[b_idx++];
    if (fmsg.msg_type == HA_SYNC_MSG_RESPONSE)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_RESPONSE, 1);
    else if (fmsg.msg_type == HA_SYNC_MSG_HELLO)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_HELLO, 1);
    else if (fmsg.msg_type == HA_SYNC_MSG_HEARTBEAT)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_HEARTBEAT, 1);

    if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ha_sync_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof(*t));
      t->msg_type = fmsg.msg_type;
      t->dst = hsm->peer_address;
      t->dst_port = hsm->dst_port;
      t->payload_len = 0;
      t->seq_number = fmsg.seq_number;
    }

  }

  while (b_idx < n_alloc && clib_fifo_elts (ptb->pending_fifo) > 0)
  {
    u32 seq;
    clib_fifo_sub1 (ptb->pending_fifo, seq);

    ha_sync_tx_packet_t pkt_info;
    if (PREDICT_FALSE (!ha_sync_tx_pool_get_by_seq (seq, &pkt_info)))
    {
      vlib_buffer_free_one (vm, bi[b_idx]);
      b_idx++;
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_POOL_MISS, 1);
      continue;
    }
    if (PREDICT_FALSE (pkt_info.length > 0 && !pkt_info.payload))
    {
      vlib_buffer_free_one (vm, bi[b_idx]);
      b_idx++;
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_POOL_MISS, 1);
      continue;
    }

    vlib_buffer_t *b = vlib_get_buffer (vm, bi[b_idx]);
    // 1. 构造 HA SYNC PACKET Header
    ha_sync_packet_header_t *h = vlib_buffer_get_current (b);
    h->magic = clib_host_to_net_u32 (HA_SYNC_MAGIC);
    h->src_ip = hsm->src_address;
    h->domain = hsm->domain_id;
    h->msg_type = pkt_info.msg_type;
    h->length = clib_host_to_net_u16 (pkt_info.length);
    h->seq_number = clib_host_to_net_u32 (pkt_info.seq_number);
    h->count = pkt_info.session_count;
    memset (h->reserve, 0, sizeof (h->reserve));

    // 2. 拷贝payload
    if (pkt_info.length > 0 && pkt_info.payload)
      clib_memcpy (h + 1, pkt_info.payload, pkt_info.length);
    b->current_length = sizeof (ha_sync_packet_header_t) + pkt_info.length;

    // 3. 封装 IP/UDP
    ha_sync_prepare_udp_header (b, b->current_length, &hsm->peer_address);

    // 4. 设置发送参数
    vnet_buffer (b)->sw_if_index[VLIB_TX] = hsm->fib_index;

    bi_to_send[sent++] = bi[b_idx++];
    if (pkt_info.msg_type == HA_SYNC_MSG_REQUEST)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_REQUEST, 1);

    if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ha_sync_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof(*t));
      t->msg_type = pkt_info.msg_type;
      t->dst = hsm->peer_address;
      t->dst_port = hsm->dst_port;
      t->payload_len = pkt_info.length;
      t->seq_number = pkt_info.seq_number;
    }

    // ******暂时先从pool移除********
    ha_sync_tx_pool_del_by_seq (pkt_info.seq_number);
    vec_free (pkt_info.payload);
    // *****************************

  }

  // 批量配置与提交
  if (PREDICT_TRUE (sent > 0))
  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
    u32 *to_next = vlib_frame_vector_args (f);
    clib_memcpy_fast (to_next, bi_to_send, sent * sizeof (u32));
    f->n_vectors = sent;
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
  }

  if (PREDICT_FALSE (b_idx < n_alloc))
  {
    vlib_buffer_free (vm, bi + b_idx, n_alloc - b_idx);
  }

  vlib_node_increment_counter (vm, node->node_index, 
                               HA_SYNC_OUTPUT_ERROR_TX, sent);

  return sent;
}

VLIB_NODE_FN (ha_sync_snapshot_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_node_runtime_t * _node) = node;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;
  return 0;
}

VLIB_NODE_FN (ha_sync_process_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_node_runtime_t * _node) = node;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;
  return 0;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ha_sync_input_worker_node) = {
  .name = "ha-sync-input-worker",
  .vector_size = sizeof (u32),
  .format_trace = format_ha_sync_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ha_sync_input_error_strings),
  .error_strings = ha_sync_input_error_strings,
  .n_next_nodes = HA_SYNC_INPUT_N_NEXT,
  .next_nodes = {
    [HA_SYNC_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ha_sync_output_worker_node) = {
  .name = "ha-sync-output-worker",
  .vector_size = sizeof (u32),
  .format_trace = format_ha_sync_output_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = ARRAY_LEN (ha_sync_output_error_strings),
  .error_strings = ha_sync_output_error_strings,
};

VLIB_REGISTER_NODE (ha_sync_snapshot_node) = {
  .name = "ha-sync-snapshot",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

VLIB_REGISTER_NODE (ha_sync_process_node) = {
  .name = "ha-sync-process",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_PROCESS,
};

VNET_FEATURE_INIT (ha_sync_input_worker_ip4_uc, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ha-sync-input-worker",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (ha_sync_input_worker_ip4_mc, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "ha-sync-input-worker",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};
#endif
/* *INDENT-ON* */

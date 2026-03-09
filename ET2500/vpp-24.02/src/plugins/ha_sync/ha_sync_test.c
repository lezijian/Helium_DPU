#include <vlib/vlib.h>
#include <ha_sync/ha_sync.h>

static clib_error_t *
ha_sync_test_tx_pool_deep_copy (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  const u32 seq = 0xA5A50001;
  u8 payload[4] = { 1, 2, 3, 4 };
  ha_sync_tx_packet_t out = { 0 };
  ha_sync_tx_packet_t verify_deleted = { 0 };

  if (!hsm->ha_sync_tx_pool || !hsm->seq_to_pool_index)
    return clib_error_return (0, "tx pool/hash is not initialized");

  (void) ha_sync_tx_pool_add (seq, HA_SYNC_MSG_REQUEST, 1, payload,
                              sizeof (payload));
  payload[0] = 9;

  if (!ha_sync_tx_pool_get_by_seq (seq, &out))
    return clib_error_return (0, "cannot read sequence 0x%08x from tx pool",
                              seq);

  if (out.length != sizeof (payload) || !out.payload)
    return clib_error_return (0, "invalid copied packet for seq 0x%08x", seq);

  if (out.payload[0] != 1)
    {
      vec_free (out.payload);
      return clib_error_return (
        0, "tx_pool_add did not copy source payload (got %u)", out.payload[0]);
    }

  ha_sync_tx_pool_del_by_seq (seq);

  /* out.payload is a deep copy and must remain valid after pool deletion */
  if (out.payload[0] != 1)
    {
      vec_free (out.payload);
      return clib_error_return (
        0, "deep copy payload became invalid after tx pool deletion");
    }

  vec_free (out.payload);

  if (ha_sync_tx_pool_get_by_seq (seq, &verify_deleted))
    {
      vec_free (verify_deleted.payload);
      return clib_error_return (0, "sequence 0x%08x still exists after delete",
                                seq);
    }

  vlib_cli_output (vm, "ha-sync test: tx-pool deep-copy OK");
  return 0;
}

static clib_error_t *
ha_sync_test_session_header_endian (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb;
  ha_sync_session_header_t *hdr;
  u16 old_packet_size;
  u8 sess[3] = { 0xAA, 0xBB, 0xCC };
  const u32 thread_index = 0;

  if (vec_len (hsm->per_thread_buffers) == 0)
    return clib_error_return (0, "per_thread_buffers is not initialized");

  ptb = &hsm->per_thread_buffers[thread_index];
  old_packet_size = hsm->packet_size;
  hsm->packet_size = HA_SYNC_MAX_TX_PAYLOAD;

  vec_reset_length (ptb->data);
  ptb->session_count = 0;

  ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT, sess,
                                 sizeof (sess));

  if (vec_len (ptb->data) < (sizeof (*hdr) + sizeof (sess)))
    {
      hsm->packet_size = old_packet_size;
      return clib_error_return (0, "session buffer size is too small");
    }

  hdr = (ha_sync_session_header_t *) ptb->data;
  if (clib_net_to_host_u16 (hdr->session_length) != sizeof (sess))
    {
      hsm->packet_size = old_packet_size;
      vec_reset_length (ptb->data);
      ptb->session_count = 0;
      return clib_error_return (0, "session_length is not network byte order");
    }

  if (hdr->app_type != HA_SYNC_APP_NAT)
    {
      hsm->packet_size = old_packet_size;
      vec_reset_length (ptb->data);
      ptb->session_count = 0;
      return clib_error_return (0, "unexpected app_type in session header");
    }

  vec_reset_length (ptb->data);
  ptb->session_count = 0;
  hsm->packet_size = old_packet_size;
  vlib_cli_output (vm, "ha-sync test: session-header endian OK");
  return 0;
}

static clib_error_t *
ha_sync_test_release_resources (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  vlib_worker_thread_barrier_sync (vm);
  ha_sync_release_resources ();
  vlib_worker_thread_barrier_release (vm);

  if (hsm->ha_sync_tx_pool || hsm->seq_to_pool_index || hsm->registrations ||
      hsm->per_thread_buffers || hsm->peer_is_set)
    return clib_error_return (0, "resource release verification failed");

  vlib_cli_output (vm, "ha-sync test: release-resources OK");
  return 0;
}

static clib_error_t *
ha_sync_test_send_fixed_packets (vlib_main_t *vm, u32 count)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb;
  u32 i;
  u32 thread_index = vlib_get_thread_index ();
  static const u8 nat_data[] = { 0x11, 0x22, 0x33, 0x44 };
  static const u8 spi_data[] = { 0x55, 0x66, 0x77, 0x88 };

  if (!hsm->enabled)
    return clib_error_return (0, "ha-sync is disabled");
  if (!hsm->peer_is_set)
    return clib_error_return (0, "peer-address is not configured");
  if (thread_index >= vec_len (hsm->per_thread_buffers))
    return clib_error_return (0, "invalid thread index %u", thread_index);
  if (count == 0)
    return clib_error_return (0, "count must be >= 1");

  ptb = &hsm->per_thread_buffers[thread_index];

  for (i = 0; i < count; i++)
    {
      u8 payload[64];
      u8 *p = payload;
      ha_sync_session_header_t sh;
      u16 payload_len;
      u32 seq_req, seq_resp, seq_hello, seq_hb;
      ha_sync_fast_msg_t msg;

      /* Fixed REQUEST payload: NAT + SPI 2 sessions */
      sh.app_type = HA_SYNC_APP_NAT;
      sh.session_length = clib_host_to_net_u16 (sizeof (nat_data));
      clib_memcpy_fast (p, &sh, sizeof (sh));
      p += sizeof (sh);
      clib_memcpy_fast (p, nat_data, sizeof (nat_data));
      p += sizeof (nat_data);

      sh.app_type = HA_SYNC_APP_SPI;
      sh.session_length = clib_host_to_net_u16 (sizeof (spi_data));
      clib_memcpy_fast (p, &sh, sizeof (sh));
      p += sizeof (sh);
      clib_memcpy_fast (p, spi_data, sizeof (spi_data));
      p += sizeof (spi_data);

      payload_len = (u16) (p - payload);
      seq_req = clib_atomic_fetch_add (&hsm->global_seq_number, 1);
      (void) ha_sync_tx_pool_add (seq_req, HA_SYNC_MSG_REQUEST, 2, payload,
                                  payload_len);
      clib_fifo_add1 (ptb->pending_fifo, seq_req);

      seq_resp = clib_atomic_fetch_add (&hsm->global_seq_number, 1);
      msg.seq_number = seq_resp;
      msg.msg_type = HA_SYNC_MSG_RESPONSE;
      clib_fifo_add1 (ptb->fast_msg_queue, msg);

      seq_hello = clib_atomic_fetch_add (&hsm->global_seq_number, 1);
      msg.seq_number = seq_hello;
      msg.msg_type = HA_SYNC_MSG_HELLO;
      clib_fifo_add1 (ptb->fast_msg_queue, msg);

      seq_hb = clib_atomic_fetch_add (&hsm->global_seq_number, 1);
      msg.seq_number = seq_hb;
      msg.msg_type = HA_SYNC_MSG_HEARTBEAT;
      clib_fifo_add1 (ptb->fast_msg_queue, msg);
    }

  vlib_cli_output (
    vm,
    "ha-sync test: enqueued %u x {REQUEST, RESPONSE, HELLO, HEARTBEAT} to %U",
    count, format_ip4_address, &hsm->peer_address);
  return 0;
}

static clib_error_t *
test_ha_sync_command_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  clib_error_t *err;
  u8 do_release = 0;
  u8 do_send_fixed = 0;
  u32 count = 1;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "release"))
        do_release = 1;
      else if (unformat (input, "send-fixed"))
        do_send_fixed = 1;
      else if (unformat (input, "count %u", &count))
        ;
      else
        return clib_error_return (0, "unknown input `%U`",
                                  format_unformat_error, input);
    }

  if (do_send_fixed)
    return ha_sync_test_send_fixed_packets (vm, count);

  err = ha_sync_test_tx_pool_deep_copy (vm);
  if (err)
    return err;

  err = ha_sync_test_session_header_endian (vm);
  if (err)
    return err;

  if (do_release)
    {
      err = ha_sync_test_release_resources (vm);
      if (err)
        return err;
    }

  vlib_cli_output (vm, "ha-sync test: all checks passed");
  return 0;
}

VLIB_CLI_COMMAND (test_ha_sync_command, static) = {
  .path = "test ha-sync",
  .short_help = "test ha-sync [send-fixed [count <n>]] [release]",
  .function = test_ha_sync_command_fn,
};

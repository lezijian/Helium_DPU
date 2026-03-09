/*
 * ha_sync.c - ha_sync plugin init and CLI
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ha_sync/ha_sync.h>

uword unformat_ip4_address (unformat_input_t *input, va_list *args);

ha_sync_main_t ha_sync_main;

static void
ha_sync_resources_init (ha_sync_main_t *hsm)
{
  u32 n_threads;
  ha_sync_per_thread_buffer_t *ptb;

  if (!hsm->ha_sync_tx_pool)
    pool_alloc (hsm->ha_sync_tx_pool, HA_SYNC_DEFAULT_POOL_SIZE);
  if (!hsm->seq_to_pool_index)
    hsm->seq_to_pool_index =
      hash_create (HA_SYNC_DEFAULT_POOL_SIZE, sizeof (uword));

  n_threads = vlib_get_n_threads ();
  vec_validate (hsm->per_thread_buffers, n_threads - 1);
  vec_foreach (ptb, hsm->per_thread_buffers)
  {
    vec_validate (ptb->data, HA_SYNC_MTU);
    vec_reset_length (ptb->data);
    ptb->session_count = 0;

    clib_fifo_validate (ptb->pending_fifo, HA_SYNC_DEFAULT_POOL_SIZE);
    clib_fifo_reset (ptb->pending_fifo);

    clib_fifo_validate (ptb->fast_msg_queue, 1024);
    clib_fifo_reset (ptb->fast_msg_queue);
  }
}

void
ha_sync_release_resources ()
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb;

  ha_sync_tx_pool_free ();

  vec_free (hsm->registrations);
  hsm->registrations = 0;
  hsm->num_registrations = 0;

  vec_foreach (ptb, hsm->per_thread_buffers)
  {
    vec_free (ptb->data);
    vec_free (ptb->pending_fifo);
    vec_free (ptb->fast_msg_queue);
  }
  vec_free (hsm->per_thread_buffers);
  hsm->per_thread_buffers = 0;

  hsm->peer_is_set = 0;
  hsm->peer_address.as_u32 = 0;
}

static clib_error_t *
ha_sync_control_command_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  int enable_disable = -1;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        enable_disable = 1;
      else if (unformat (input, "disable"))
        enable_disable = 0;
      else
        return clib_error_return (0, "unknown input `%U`", format_unformat_error,
                                  input);
    }

  if (enable_disable < 0)
    return clib_error_return (0, "usage: ha_sync control <enable|disable>");

  vlib_worker_thread_barrier_sync (vm);
  if (enable_disable)
    {
      ha_sync_resources_init (hsm);
      hsm->enabled = 1;
    }
  else
    {
      hsm->enabled = 0;
      ha_sync_release_resources ();
    }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

static clib_error_t *
ha_sync_set_src_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ip4_address_t ip4;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set src-address <ip4>");

  hsm->src_address = ip4;
  return 0;
}

static clib_error_t *
ha_sync_set_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ip4_address_t ip4;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set peer-address <ip4>");

  hsm->peer_address = ip4;
  hsm->peer_is_set = 1;
  return 0;
}

static clib_error_t *
ha_sync_clear_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  hsm->peer_is_set = 0;
  hsm->peer_address.as_u32 = 0;
  return 0;
}

static clib_error_t *
ha_sync_set_domain_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 domain_id;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%u", &domain_id))
    return clib_error_return (0, "usage: ha_sync set domain <domain-id>");

  hsm->domain_id = domain_id;
  return 0;
}

static clib_error_t *
ha_sync_set_packet_size_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 packet_size;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%u", &packet_size))
    return clib_error_return (0, "usage: ha_sync set packet_size <bytes>");

  if (packet_size == 0 || packet_size > HA_SYNC_MAX_TX_PAYLOAD)
    return clib_error_return (0, "packet_size must be in [1, %u]",
                              HA_SYNC_MAX_TX_PAYLOAD);

  hsm->packet_size = (u16) packet_size;
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ha_sync_control_command, static) = {
  .path = "ha_sync control",
  .short_help = "ha_sync control <enable|disable>",
  .function = ha_sync_control_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_src_address_command, static) = {
  .path = "ha_sync set src-address",
  .short_help = "ha_sync set src-address <ip4>",
  .function = ha_sync_set_src_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_peer_address_command, static) = {
  .path = "ha_sync set peer-address",
  .short_help = "ha_sync set peer-address <ip4>",
  .function = ha_sync_set_peer_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_clear_peer_address_command, static) = {
  .path = "ha_sync clear peer-address",
  .short_help = "ha_sync clear peer-address",
  .function = ha_sync_clear_peer_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_domain_command, static) = {
  .path = "ha_sync set domain",
  .short_help = "ha_sync set domain <domain-id>",
  .function = ha_sync_set_domain_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_packet_size_command, static) = {
  .path = "ha_sync set packet_size",
  .short_help = "ha_sync set packet_size <bytes>",
  .function = ha_sync_set_packet_size_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ha_sync_init (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  hsm->vlib_main = vm;
  hsm->vnet_main = vnet_get_main ();
  hsm->enabled = 0;
  hsm->fib_index = 0;
  hsm->src_address.as_u32 = clib_host_to_net_u32 (0x7f000001); /* 127.0.0.1 */
  hsm->src_port = HA_SYNC_UDP_PORT;
  hsm->dst_port = HA_SYNC_UDP_PORT;
  hsm->domain_id = HA_SYNC_DEFAULT_DOMAIN_ID;
  hsm->packet_size = HA_SYNC_MAX_TX_PAYLOAD;
  hsm->heartbeat_interval_sec = HA_SYNC_HEARTBEAT_INTERVAL_SEC;
  hsm->heartbeat_max_fail_counts = HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS;
  hsm->peer_is_set = 0;
  hsm->peer_address.as_u32 = 0;
  hsm->num_registrations = 0;
  
  clib_spinlock_init (&hsm->tx_lock);
  ha_sync_resources_init (hsm);

  return 0;
}

VLIB_INIT_FUNCTION (ha_sync_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "HA sync framework plugin",
};
/* *INDENT-ON* */

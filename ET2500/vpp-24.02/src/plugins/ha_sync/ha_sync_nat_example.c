// 示例 NAT 会话同步
#include <ha_sync/ha_sync.h>


typedef struct __attribute__ ((packed))
{
  ip4_address_t in_src_addr;
  ip4_address_t in_dst_addr;
  u16 in_src_port;
  u16 in_dst_port;
  u8 protocol;
} nat44_5tuple_t;

typedef struct
{
  u8 sync_enabled;
} ha_sync_nat_ctx_t;

static ha_sync_nat_ctx_t ha_sync_nat_ctx;




// 应用 NAT 会话
static void
ha_sync_nat_session_apply_cb (u32 app_type, void *ctx, u8 *session,
                              u16 session_len)
{
  // 需要实现的内容，session 和 session_len是从ha_sync传来的会话数据
  // todo
}

static int
ha_sync_nat_snapshot_send_cb (u32 app_type, void *ctx)
{
  // 读取会话表，调用加入到会话表
  // ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT, (u8 *) entry,
  //                                sizeof (*entry));
  // 每读取固定条目 如500条，记录读取位置，先让出cpu，返回1。
  // 如果ha_sync 收到返回值为1，后续还会继续调用该函数直到返回0。
  // todo，当前快照的读取还未完成，可以先做 会话应用和会话发送。
  return 0;
}

static ha_sync_session_registration_t ha_sync_nat_registration = {
  .app_type = HA_SYNC_APP_NAT,
  .context = &ha_sync_nat_ctx,
  .snapshot_send_cb = ha_sync_nat_snapshot_send_cb,
  .session_apply_cb = ha_sync_nat_session_apply_cb,
};

// 在NAT的init中，调用 ha_sync_register_session_application 注册会话应用
int ha_sync_nat_register_example (void)
{
  ha_sync_nat_ctx.sync_enabled = 1;
  return ha_sync_register_session_application (&ha_sync_nat_registration);
}

// 在NAT的deinit中，调用 ha_sync_unregister_session_application 注销会话应用
void
ha_sync_nat_unregister_example (void)
{
  ha_sync_nat_ctx.sync_enabled = 0;
  (void) ha_sync_unregister_session_application (HA_SYNC_APP_NAT);
}

// 增量会话同步的示例
void ha_sync_nat_enqueue_session_example (const nat44_5tuple_t *entry)
{
  u32 thread_index = vlib_get_thread_index ();

  if (!ha_sync_nat_ctx.sync_enabled || !entry)
    return;

  // 此处 调用 ha_sync_per_thread_buffer_add 加入会话数据，所有会话数据都加入到pending_fifo中
  // 不支持跨线程发送，此处的thread_index只能是当前线程
  ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT, (u8 *) entry,
                                 sizeof (*entry));
}

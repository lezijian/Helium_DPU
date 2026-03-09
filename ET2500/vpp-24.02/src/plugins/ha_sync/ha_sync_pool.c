#include <ha_sync/ha_sync.h>


u32 ha_sync_tx_pool_add (u32 seq, u8 msg_type, u8 session_count, u8 *payload, u16 payload_len)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u32 index;
    u8 *payload_vec = 0;
    u8 *old_payload_to_free = 0;

    if (payload_len > 0)
    {
        vec_validate(payload_vec, payload_len - 1);
        clib_memcpy(payload_vec, payload, payload_len);
    }

    clib_spinlock_lock(&hsm->tx_lock);

    uword *p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        ha_sync_tx_packet_t *old_req = pool_elt_at_index (hsm->ha_sync_tx_pool, p[0]);
        old_payload_to_free = old_req->payload;
        index = p[0];
        req = old_req;
    } else {
        pool_get(hsm->ha_sync_tx_pool, req);
        index = req - hsm->ha_sync_tx_pool;
        hash_set(hsm->seq_to_pool_index, seq, index);
    }

    req->seq_number = seq;
    req->msg_type = msg_type;
    req->length = payload_len;
    req->payload = payload_vec;
    req->session_count = session_count;

    clib_spinlock_unlock(&hsm->tx_lock);

    if (old_payload_to_free)
        vec_free(old_payload_to_free);

    return index;
}


int ha_sync_tx_pool_get_by_seq (u32 seq, ha_sync_tx_packet_t *out_data)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    uword *p;
    int found = 0;
    u8 *payload_copy = 0;

    clib_spinlock_lock(&hsm->tx_lock);
    p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        ha_sync_tx_packet_t *req = pool_elt_at_index (hsm->ha_sync_tx_pool, p[0]);
        out_data->seq_number = req->seq_number;
        out_data->msg_type = req->msg_type;
        out_data->session_count = req->session_count;
        out_data->length = req->length;
        out_data->payload = 0;
        if (req->length > 0 && req->payload)
        {
            vec_validate(payload_copy, req->length - 1);
            clib_memcpy(payload_copy, req->payload, req->length);
            out_data->payload = payload_copy;
        }
        found = (req->length == 0 || out_data->payload != 0);
    }
    clib_spinlock_unlock(&hsm->tx_lock);

    if (!found && payload_copy)
        vec_free(payload_copy);
    return found;
}


void ha_sync_tx_pool_del_by_seq (u32 seq)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    uword *p;
    u8 *vec_to_free = 0;

    clib_spinlock_lock(&hsm->tx_lock);
    p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        u32 index = p[0];
        ha_sync_tx_packet_t *req = pool_elt_at_index (hsm->ha_sync_tx_pool, index);
        vec_to_free = req->payload;
        req->payload = 0;
        req->length = 0;
        pool_put_index(hsm->ha_sync_tx_pool, index);
        hash_unset(hsm->seq_to_pool_index, seq);
    }
    clib_spinlock_unlock(&hsm->tx_lock);

    if (vec_to_free)
        vec_free(vec_to_free);
}

void ha_sync_pool_reset_and_clear ()
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u8 **vecs_to_free = 0;

    clib_spinlock_lock(&hsm->tx_lock);
    if (hsm->ha_sync_tx_pool)
    {
        pool_foreach (req, hsm->ha_sync_tx_pool)
        {
            if (req->payload)
            {
                vec_add1 (vecs_to_free, req->payload);
                req->payload = 0;
            }
        }

        pool_free(hsm->ha_sync_tx_pool);
        hsm->ha_sync_tx_pool = 0;
    }

    if (hsm->seq_to_pool_index)
    {
        hash_free(hsm->seq_to_pool_index);
        hsm->seq_to_pool_index = 0;
    }

    clib_spinlock_unlock(&hsm->tx_lock);

    u8 **v;
    vec_foreach(v, vecs_to_free)
    {
        vec_free(*v);
    }
    vec_free(vecs_to_free);
    
}


void ha_sync_tx_pool_free ()
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u8 **vecs_to_free = 0;

    clib_spinlock_lock(&hsm->tx_lock);

    if (hsm->ha_sync_tx_pool)
    {
        pool_foreach (req, hsm->ha_sync_tx_pool)
        {
          if (req->payload)
              vec_add1 (vecs_to_free, req->payload);
        }
        pool_free(hsm->ha_sync_tx_pool);
        hsm->ha_sync_tx_pool = 0;
    }

    if (hsm->seq_to_pool_index)
    {
        hash_free(hsm->seq_to_pool_index);
        hsm->seq_to_pool_index = 0;
    }

    clib_spinlock_unlock(&hsm->tx_lock);

    u8 **v;
    vec_foreach(v, vecs_to_free)
    {
        vec_free(v[0]);
    }
    vec_free(vecs_to_free);

}

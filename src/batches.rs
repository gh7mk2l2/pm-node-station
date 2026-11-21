//! 批次激活/停用：所有入口共用 advisory 锁，避免自动同步与后台手动切换交叉提交。

use sqlx::{Postgres, Transaction};

/// 批次激活锁（"PMNS" 的 ASCII 码拼合，固定值）
pub const BATCH_ACTIVATION_LOCK_ID: i64 = 0x504D_4E53;

async fn lock_batch_activation(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BATCH_ACTIVATION_LOCK_ID)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 串行化“停旧 → 启新”，保证任一提交时刻每个分级最多只有一个激活批次
pub async fn activate_batch(tx: &mut Transaction<'_, Postgres>, id: i64) -> sqlx::Result<()> {
    lock_batch_activation(tx).await?;
    // 只停用与目标批次同一分级的激活批次；另一分级不受影响
    let tier: Option<i16> = sqlx::query_scalar("SELECT tier FROM node_batches WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(tier) = tier else {
        return Err(sqlx::Error::RowNotFound);
    };
    sqlx::query("UPDATE node_batches SET is_active = FALSE WHERE is_active = TRUE AND tier = $1")
        .bind(tier)
        .execute(&mut **tx)
        .await?;
    let n = sqlx::query("UPDATE node_batches SET is_active = TRUE WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// 停用也进入同一临界区，避免与另一个请求的激活操作互相穿插
pub async fn deactivate_batch(tx: &mut Transaction<'_, Postgres>, id: i64) -> sqlx::Result<()> {
    lock_batch_activation(tx).await?;
    sqlx::query("UPDATE node_batches SET is_active = FALSE WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

use sqlx::PgPool;

/// 写审计日志。审计失败不阻断主流程，但要留下日志痕迹。
pub async fn write_audit(
    pool: &PgPool,
    actor_user_id: Option<i64>,
    action: &str,
    target_type: Option<&str>,
    target: Option<&str>,
    detail: serde_json::Value,
) {
    let res = sqlx::query(
        "INSERT INTO audit_logs (actor_user_id, action, target_type, target, detail) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor_user_id)
    .bind(action)
    .bind(target_type)
    .bind(target)
    .bind(detail)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::error!(error = %e, action, "audit write failed");
    }
}

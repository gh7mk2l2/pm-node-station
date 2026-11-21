//! 节点延迟实测（已永久停用）。
//!
//! 2026-11-14 Wing 紧急要求：千万不要在 InstaBox 机器上检测节点状态/测延迟，
//! 否则会被封机器。本文件的主动探测逻辑已删除：test_nodes 不连接任何节点，
//! retest_batch 直接返回 0。延迟只能由用户自己的设备/浏览器端测。

use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct NodeLatency {
    pub index: usize,
    pub latency_ms: Option<i64>,
    pub online: bool,
}

/// 对一批节点 URI 做延迟测量——已停用：不连接任何节点，全部返回未测出。
pub async fn test_nodes(nodes: &[String]) -> Vec<NodeLatency> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, _)| NodeLatency {
            index: i,
            latency_ms: None,
            online: false,
        })
        .collect()
}

/// 对指定批次的节点做一轮测速并写回 node_latency——已停用：直接返回 0，不写库、不连节点。
pub async fn retest_batch(pool: &PgPool, batch_id: i64) -> Result<usize, String> {
    let _ = (pool, batch_id);
    Ok(0)
}

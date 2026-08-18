//! Proves the zero-setup test path works before any schema exists.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[tokio::test]
async fn postgres_container_starts_and_answers() {
    let db = brolly_test_support::postgres().await;

    let answer: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&db.pool)
        .await
        .expect("query the provisioned database");

    assert_eq!(answer, 1);
}

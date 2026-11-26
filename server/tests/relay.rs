//! `requestCrawl` on startup (stage 3, E), against a stand-in relay on a real
//! loopback port.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;
use axum::routing::post;
use brolly_server::relay::{Backoff, Relay};
use serde_json::Value;

/// A relay that refuses the first `refusals` invitations, then accepts, and
/// records every body it was sent.
async fn stub_relay(refusals: usize) -> (String, Arc<Mutex<Vec<Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let record = seen.clone();
    let app = axum::Router::new().route(
        "/xrpc/com.atproto.sync.requestCrawl",
        post(move |Json(body): Json<Value>| {
            let record = record.clone();
            async move {
                let mut seen = record.lock().unwrap();
                seen.push(body);
                if seen.len() <= refusals {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (origin, seen)
}

const FAST: Backoff = Backoff {
    first: Duration::from_millis(5),
    cap: Duration::from_millis(20),
};

#[tokio::test]
async fn the_relay_is_invited_with_the_instances_hostname() {
    let (origin, seen) = stub_relay(0).await;
    let relay = Relay::for_tests(&origin).unwrap();

    assert_eq!(relay.announce("brolly.test", FAST).await, 1);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![serde_json::json!({"hostname": "brolly.test"})]
    );
}

#[tokio::test]
async fn a_relay_that_refuses_is_asked_again_until_it_accepts() {
    let (origin, seen) = stub_relay(3).await;
    let relay = Relay::for_tests(&origin).unwrap();

    // Three refusals, then the fourth lands — and the loop stops there.
    assert_eq!(relay.announce("brolly.test", FAST).await, 4);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(seen.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn an_unreachable_relay_is_a_failed_attempt_not_a_panic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let relay = Relay::for_tests(&origin).unwrap();
    assert!(relay.request_crawl("brolly.test").await.is_err());
}

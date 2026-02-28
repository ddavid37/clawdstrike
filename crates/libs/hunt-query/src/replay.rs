//! NATS JetStream replay consumer for historical envelope retrieval.

use async_nats::jetstream::consumer::pull;
use serde_json::Value;
use tokio_stream::StreamExt;

use crate::error::{Error, Result};
use crate::query::{EventSource, HuntQuery};
use crate::timeline::{self, TimelineEvent};

/// Replay envelopes from a single JetStream stream, filtered by query predicates.
pub async fn replay_stream(
    js: &async_nats::jetstream::Context,
    source: &EventSource,
    query: &HuntQuery,
    verify: bool,
) -> Result<Vec<TimelineEvent>> {
    let stream_name = source.stream_name();

    // Get stream — if missing, warn and return empty
    let stream = match js.get_stream(stream_name).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("stream {stream_name} not found, skipping: {e}");
            return Ok(Vec::new());
        }
    };

    // Build consumer config with time-based delivery if start is specified
    let deliver_policy = if let Some(ref start) = query.start {
        let ts = start.timestamp();
        let offset_dt = time::OffsetDateTime::from_unix_timestamp(ts)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        async_nats::jetstream::consumer::DeliverPolicy::ByStartTime {
            start_time: offset_dt,
        }
    } else {
        async_nats::jetstream::consumer::DeliverPolicy::All
    };

    let config = pull::Config {
        filter_subject: source.subject_filter().to_string(),
        deliver_policy,
        ..Default::default()
    };

    let consumer = stream.create_consumer(config).await.map_err(|e| {
        Error::JetStream(format!("failed to create consumer on {stream_name}: {e}"))
    })?;

    let mut messages = consumer.messages().await.map_err(|e| {
        Error::JetStream(format!(
            "failed to get message stream from {stream_name}: {e}"
        ))
    })?;

    let mut events = Vec::new();

    while let Some(msg_result) = messages.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("error reading message from {stream_name}: {e}");
                continue;
            }
        };

        // Parse payload as JSON envelope
        let payload: Value = match serde_json::from_slice(&msg.payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("skipping non-JSON message from {stream_name}: {e}");
                continue;
            }
        };

        // Parse envelope into TimelineEvent
        if let Some(event) = timeline::parse_envelope(&payload, verify) {
            // Stop if past end time
            if let Some(ref end) = query.end {
                if event.timestamp > *end {
                    break;
                }
            }

            if query.matches(&event) {
                events.push(event);
                if events.len() >= query.limit {
                    break;
                }
            }
        }
    }

    Ok(events)
}

/// Replay and merge envelopes from all query sources.
pub async fn replay_all(
    query: &HuntQuery,
    nats_url: &str,
    nats_creds: Option<&str>,
    verify: bool,
) -> Result<Vec<TimelineEvent>> {
    let auth = nats_creds.map(|c| spine::nats_transport::NatsAuthConfig {
        creds_file: Some(c.to_string()),
        token: None,
        nkey_seed: None,
    });

    let client = spine::nats_transport::connect_with_auth(nats_url, auth.as_ref())
        .await
        .map_err(|e| Error::Nats(format!("failed to connect to NATS at {nats_url}: {e}")))?;

    let js = spine::nats_transport::jetstream(client);

    let mut all_events = Vec::new();

    for source in &query.effective_sources() {
        match replay_stream(&js, source, query, verify).await {
            Ok(events) => all_events.extend(events),
            Err(e) => {
                tracing::warn!("failed to replay {source} stream: {e}");
            }
        }
    }

    let mut merged = timeline::merge_timeline(all_events);
    merged.truncate(query.limit);
    Ok(merged)
}

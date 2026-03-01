#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hunt Scan — MCP agent scanning and vulnerability detection.
//!
//! This crate provides the core scanning engine for `clawdstrike hunt scan`.
//! It discovers AI agent MCP configurations, introspects servers, and detects
//! vulnerabilities in tool descriptions and configurations.

pub mod analysis;
pub mod discovery;
pub mod mcp_client;
pub mod models;
pub mod packages;
pub mod policy_eval;
pub mod query_filter;
pub mod receipt;
pub mod redact;
pub mod skills;
pub mod storage;

/**
 * @backbay/sdk - Adapter Internals
 *
 * This module re-exports types and utilities from @backbay/adapter-core
 * for advanced use cases. For most users, the main Clawdstrike class provides
 * a simpler API.
 *
 * @example
 * ```typescript
 * import { adapters } from '@backbay/sdk';
 * const { BaseToolInterceptor, PolicyEventFactory } = adapters;
 * ```
 *
 * @packageDocumentation
 */

// Re-export everything from adapter-core
// This allows users to do: import { adapters } from '@backbay/sdk'
export * from '@backbay/adapter-core';

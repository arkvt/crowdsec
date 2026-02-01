// Package pusher provides gRPC-based data synchronization from probe to backend.
//
// This package implements a bidirectional streaming gRPC client that:
// - Sends access_logs, alerts, and decisions data to the backend
// - Receives commands from the backend for execution
// - Maintains persistent cursor state for reliable sync
//
// The main entry point is NewPusher() which creates a Pusher instance.
// Call Run() to start the sync loops and Stop() to gracefully shutdown.
package pusher

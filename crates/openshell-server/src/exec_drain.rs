// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-flight exec streams, counted so graceful shutdown can wait for them.
//!
//! An exec is relayed over the supervisor session this replica holds, so it
//! cannot fail over: when the process exits, every exec it is relaying fails
//! partway through, after the command may already have had side effects. The
//! connection tasks serving those streams are detached, so nothing else keeps
//! the process alive for them.
//!
//! A handler takes its guard *before* it asks the session registry for a
//! relay. Shutdown starts draining the registry first and waits here second,
//! so every exec is either refused by the registry or counted here — there is
//! no order of the two steps in which one is admitted and not waited for.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// Counter of exec streams in flight on this replica.
#[derive(Debug, Default)]
pub struct ExecDrain {
    in_flight: AtomicUsize,
    idle: Notify,
}

/// Held for the life of one exec stream; releases its count on drop.
#[derive(Debug)]
pub struct ExecGuard {
    drain: Arc<ExecDrain>,
}

impl ExecDrain {
    /// Count one exec until the returned guard is dropped.
    pub fn track(self: &Arc<Self>) -> ExecGuard {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        ExecGuard {
            drain: Arc::clone(self),
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Wait until no exec is in flight, or `timeout` passes.
    ///
    /// Returns whether the count reached zero.
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                // Registered before the count is read, so a guard dropped
                // between the read and the await still wakes this loop.
                let notified = self.idle.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.in_flight() == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}

impl Drop for ExecGuard {
    fn drop(&mut self) {
        if self.drain.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.drain.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_idle_returns_at_once_with_nothing_in_flight() {
        let drain = Arc::new(ExecDrain::default());
        assert!(drain.wait_idle(Duration::ZERO).await);
    }

    #[tokio::test]
    async fn wait_idle_returns_when_the_last_exec_finishes() {
        let drain = Arc::new(ExecDrain::default());
        let first = drain.track();
        let second = drain.track();
        assert_eq!(drain.in_flight(), 2);

        let waiter = {
            let drain = Arc::clone(&drain);
            tokio::spawn(async move { drain.wait_idle(Duration::from_secs(5)).await })
        };
        drop(first);
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(second);
        assert!(waiter.await.unwrap());
        assert_eq!(drain.in_flight(), 0);
    }

    #[tokio::test]
    async fn wait_idle_gives_up_at_the_deadline() {
        let drain = Arc::new(ExecDrain::default());
        let _held = drain.track();
        assert!(!drain.wait_idle(Duration::from_millis(20)).await);
        assert_eq!(drain.in_flight(), 1);
    }
}

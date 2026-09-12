// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Print subset selections for a fixed fleet, so a second implementation of
//! [`openshell_core::gateway_fleet::subset_for`] can be diffed against this
//! one rather than against a shared description of it.
//!
//! `sandbox-api` has such an implementation in TypeScript. Run this and its
//! counterpart and compare the output whenever either side changes.

use openshell_core::gateway_fleet::subset_for;

fn main() {
    let members: Vec<String> = (1..=7)
        .map(|i| format!("10-42-0-{i}.openshell-headless.sandbox.svc.cluster.local:8080"))
        .collect();

    for sandbox_id in ["sbx-1", "sbx-abc", "9f3c-4d2e", "", &"x".repeat(64)] {
        for subset_size in [1usize, 2, 3] {
            println!(
                "{sandbox_id}|{subset_size}|{}",
                subset_for(sandbox_id, &members, subset_size).join(",")
            );
        }
    }
}

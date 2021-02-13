// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

// The only way spinning can cancel is by polling.
pub const Cancellation = struct {
    context: usize,
    isCancelledFn: fn(*Cancellation) bool,
};

// Futex implementation which blocks via std.time.sleep()
pub const Futex = struct {
    pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
        while (true) : (atomic.spinLoopHint()) {
            if (atomic.load(ptr, .SeqCst) != expected) {
                return;
            }

            if (cancellation) |cc| {
                if ((cc.isCancelledFn)(cc)) {
                    return error.Cancelled;
                }
            }
        }
    }

    pub fn notifyOne(ptr: *const u32) void {
        // no-op
    }

    pub fn notifyAll(ptr: *const u32) void {
        // no-op
    }

    pub fn yield(iteration: usize) bool {
        // nothing to do here since we will eventually spin in wait() above.
        return false;
    }
};
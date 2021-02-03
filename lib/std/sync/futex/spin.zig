// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
    while (true) : (atomic.spinLoopHint()) {
        if (atomic.load(ptr, .Acquire) != expected) {
            return;
        }

        if (timeout != null) {
            return error.TimedOut;
        }
    }
}

pub fn wake(ptr: *const u32) void {
    // no-op
}

pub fn yield(iteration: usize) bool {
    if (iteration > 100) {
        return false;
    }

    atomic.spinLoopHint();
    return true;
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const atomic = @import("../atomic.zig");
const ParkingLot = @import("../primitives.zig").core.ParkingLot;

pub usingnamespace ParkingLot(struct {
    pub const Futex = struct {
        pub const Cancellation = void;

        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
            while (true) : (atomic.spinLoopHint()) {
                if (atomic.load(ptr, .SeqCst) != expected) {
                    return;
                }

                if (cancellation != null) {
                    return error.Cancelled;
                }
            }
        }

        pub fn wake(ptr: *const u32) void {
            // no-op
        }

        pub fn yield(iteration: usize) bool {
            return false;
        }
    };
});

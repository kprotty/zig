// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../../std.zig");
const atomic = @import("../../atomic.zig");

const assert = std.debug.assert;
const builtin = std.builtin;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

/// Implements a ParkingLot Event using the provided abstractions.
pub fn FutexEvent(
    comptime Futex: type,
    comptime Cancellation: type,
) type {
    return struct {
        state: State,

        const Self = @This();
        const State = enum(u32) {
            empty,
            waiting,
            notified,
        };

        pub fn init(self: *Self) void {
            self.state = .empty;
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            self.state = .empty;
        }

        pub fn set(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBefore(@ptrToInt(self));
            }

            switch (atomic.swap(&self.state, .notified, .Release)) {
                .empty => {},
                .waiting => Futex.notifyOne(@ptrCast(*const u32, &self.state)),
                .notified => unreachable,
            }
        }

        pub fn wait(self: *Self, cancellation: ?*Cancellation) error{Cancelled}!void {
            defer if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            };
            
            if (atomic.compareAndSwap(
                &self.state,
                .empty,
                .waiting,
                .Acquire,
                .Acquire,
            )) |state| {
                assert(state == .notified);
                return;
            }

            while (true) {
                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.waiting),
                    cancellation,
                ) catch break;

                switch (atomic.load(&self.state, .Acquire)) {
                    .empty => unreachable,
                    .waiting => continue,
                    .notified => return,
                }
            }

            const state = atomic.compareAndSwap(
                &self.state,
                .waiting,
                .empty,
                .Acquire,
                .Acquire,
            ) orelse return error.Cancelled;
            assert(state == .notified);
        }

        pub fn yield(iteration: usize) bool {
            return Futex.yield(iteration);
        }
    };
}
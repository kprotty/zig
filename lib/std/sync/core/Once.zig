// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn Once(comptime parking_lot: type) type {
    if (@hasDecl(parking_lot.backend, "CoreOnce")) {
        return parking_lot.backend.CoreOnce;
    }

    return struct {
        state: State = .uninit,

        const Self = @This();
        const State = enum(u8) {
            uninit,
            updating,
            init,
        };

        pub inline fn call(self: *Self, initFn: anytype) void {
            const state = atomic.load(&self.state, .Acquire);
            if (state != .init) {
                self.wait(state, initFn);
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }
        }

        fn wait(self: *Self, current_state: State, initFn: anytype) void {
            @setCold(true);
            
            var state = current_state;
            while (state == .uninit) {
                if (atomic.tryCompareAndSwap(
                    &self.state,
                    .uninit,
                    .updating,
                    .Acquire,
                    .Acquire,
                )) |updated| {
                    state = updated;
                    continue;
                }

                if (helgrind) |hg| {
                    hg.annotateHappensBefore(@ptrToInt(self));
                }

                const ret = initFn();
                atomic.store(&self.state, .init, .Release);
                return;
            }

            if (state == .updating) {
                const Parker = struct {
                    once: *Self,

                    pub fn onValidate(parker: @This()) ?parking_lot.Token {
                        return switch (atomic.load(&parker.once.state, .Acquire)) {
                            .uninit => unreachable,
                            .updating => 0,
                            .init => null,
                        };
                    }

                    pub fn onBeforeWait(parker: @This()) void {
                        // no-op
                    }

                    pub fn onCancel(parker: @This(), unparked: parking_lot.Unparked) void {
                        // no-op
                    }
                };

                _ = parking_lot.park(
                    @ptrToInt(self),
                    null,
                    Parker{ .once = self },
                ) catch |err| switch (err) {
                    error.Invalidated => {},
                    error.Cancelled => unreachable,
                };
            }
        }
    };
}
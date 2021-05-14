// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

pub fn ResetEvent(comptime WaitQueue: type) type {
    return extern struct {
        state: State = .unset,

        const Self = @This();
        const State = enum(u8) {
            unset,
            waiting,
            set,
        };

        pub fn init(is_set: bool) Self {
            return Self{ .state = if (is_set) .set else .unset };
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(self.state != .waiting);
            self.* = undefined;
        }

        pub fn isSet(self: *const Self) bool {
            return atomic.load(&self.is_set, .Acquire);
        }

        pub fn wait(self: *Self) callconv(.Inline) void {
            return self.waitFast(null) catch unreachable;
        }

        pub fn tryWaitFor(self: *Self, duration: std.time.Duration) error{TimedOut}!void {
            const timeout = WaitQueue.Instant.now().after(duration);
            const deadline = timeout orelse return error.TimedOut;
            return self.tryWaitUntil(deadline);
        }

        pub fn tryWaitUntil(self: *Self, deadline: WaitQueue.WaitInstant) callconv(.Inline) error{TimedOut}!void {
            return self.waitFast(deadline);
        }

        fn waitFast(self: *Self, deadline: ?WaitQueue.WaitInstant) callconv(.Inline) error{TimedOut}!void {
            if (self.isSet()) return;
            return self.waitSlow(deadline);
        }

        fn waitSlow(self: *Self, deadline: ?WaitQueue.WaitInstant) error{TimedOut}!void {
            @setCold(true);

            var adaptive_spin: u8 = 0;
            var state = atomic.load(&self.state, .Acquire);
            while (true) {
                if (state == .set) {
                    return;
                }

                if (state == .unset) {
                    if (adaptive_spin <= 3) {
                        var spin = @as(usize, 1) << @intCast(std.math.Log2Int(usize), adaptive_spin);
                        while (spin > 0) : (spin -= 1) {
                            atomic.spinLoopHint();
                        }

                        adaptive_spin += 1;
                        state = atomic.load(&self.state, .Acquire);
                        continue;
                    }

                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        .unset,
                        .waiting,
                        .Acquire,
                        .Acquire,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                const WaitContext = struct {
                    reset_event: *Self,

                    pub fn onValidate(this: @This()) ?usize {
                        const current_state = atomic.load(&this.reset_event.state, .Acquire);
                        if (current_state != .waiting) return null;
                        return 0;
                    }

                    pub fn onBeforeWait(this: @This()) void {}
                    pub fn onTimedOut(this: @This(), _: WaitQueue.Waiting) void {}
                };

                WaitQueue.wait(
                    @ptrToInt(self),
                    deadline,
                    WaitContext{ .reset_event = self },
                ) catch |err| switch (err) {
                    error.TimedOut => return error.TimedOut,
                    error.Invalidated => {},
                };

                adaptive_spin = 0;
                state = atomic.load(&self.state, .Acquire);
            }
        }

        fn notify(self: *Self) void {
            @setCold(true);

            const WakeContext = struct {
                pub fn onWake(this: *@This(), _: WaitQueue.Waiting) WaitQueue.Waking {
                    return .Wake;
                }

                pub fn onBeforeWake(this: @This()) void {}
            };

            return WaitQueue.wake(
                @ptrToInt(self),
                WakeContext{},
            );
        }

        pub fn set(self: *Self) callconv(.Inline) void {
            switch (atomic.swap(&self.state, .set, .Release)) {
                .unset => {},
                .waiting => self.notify(),
                .set => {},
            }
        }

        pub fn reset(self: *Self) void {
            if (std.debug.runtime_safety) {
                const state = atomic.load(&self.state, .Relaxed);
                std.debug.assert(state != .waiting);
            }

            atomic.store(&self.state, .unset, .Relaxed);
        }        
    };
}
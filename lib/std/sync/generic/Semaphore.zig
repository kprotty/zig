// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

pub fn Semaphore(comptime WaitQueue: type) type {
    return extern struct {
        permits: usize = 0,

        const Self = @This();

        const WAITING: usize = 1 << 0;
        const PERMIT: usize = 1 << 1;
        pub const MAX = std.math.maxInt(usize) >> 1;

        pub fn init(permits: usize) Self {
            std.debug.assert(permits <= MAX);
            return Self{ .permits = permits << 1 };
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(self.state & WAITING == 0);
            self.* = undefined;
        }

        pub fn wait(self: *Self) callconv(.Inline) void {
            return self.acquire(1);
        }

        pub fn tryWait(self: *const Self) callconv(.Inline) bool {
            return self.tryAcquire(1);
        }

        pub fn tryWaitFor(self: *Self, duration: std.time.Duration) callconv(.Inline) error{TimedOut}!void {
            return self.tryAcquireFor(1, duration);
        }

        pub fn tryWaitUntil(self: *Self, deadline: WaitQueue.WaitInstant) callconv(.Inline) error{TimedOut}!void {
            return self.tryAcquireUntil(1, deadline);
        }

        pub fn post(self: *Self) callconv(.Inline) void {
            return self.release(1);
        }

        pub fn acquire(self: *Self, permits: usize) callconv(.Inline) void {
            return self.tryAcquirePermits(permits, null) catch unreachable;
        }

        pub fn tryAcquire(self: *Self, permits: usize) callconv(.Inline) bool {
            const state = atomic.load(&self.state, .Relaxed);
            return self.tryAcquireWith(state, permits) == null;
        }

        fn tryAcquireWith(self: *Self, current_state: usize, permits: usize) ?usize {
            std.debug.assert(permits <= MAX);
            const num_permits = permits * PERMIT;

            var state = current_state;
            while (true) {
                if (state < num_permits) {
                    return state;
                }

                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    state - num_permits,
                    .Acquire,
                    .Relaxed,
                ) orelse return null;
            }
        }

        pub fn tryAcquireFor(
            self: *Self, 
            permits: usize, 
            duration: std.time.Duration,
        ) error{TimedOut}!void {
            const timeout = WaitQueue.Instant.now().after(duration);
            const deadline = timeout orelse return error.TimedOut;
            return self.tryAcquireUntil(permits, deadline);
        }

        pub fn tryAcquireUntil(
            self: *Self, 
            permits: usize, 
            deadline: WaitQueue.WaitInstant,
        ) callconv(.Inline) error{TimedOut}!void {
            return self.tryAcquirePermits(permits, deadline);
        }

        fn tryAcquirePermits(
            self: *Self, 
            permits: usize,
            deadline: ?WaitQueue.WaitInstant,
        ) error{TimedOut}!void {
            @setCold(true);

            var adaptive_spin: u8 = 0;
            var state = atomic.load(&self.state, .Relaxed);
            state = self.tryAcquireWith(state, permits) orelse return;

            while (true) {
                if (state >= permits) {
                    state = self.tryAcquireWith(state, permits) orelse return;
                    continue;
                }

                if (state & WAITING != 0) {
                    if (adaptive_spin <= 3) {
                        var spin = @as(usize, 1) << @intCast(std.math.Log2Int(usize), adaptive_spin);
                        while (spin > 0) : (spin -= 1) {
                            atomic.spinLoopHint();
                        }

                        adaptive_spin += 1;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state | WAITING,
                        .Relaxed,
                        .Relaxed,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                var wait_context = WaitContext{
                    .semaphore = self,
                    .permits = permits,
                };

                WaitQueue.wait(
                    @ptrToInt(self),
                    deadline,
                    &wait_context,
                ) catch |err| switch (err) {
                    error.TimedOut => return error.TimedOut,
                    error.Invalidated => {},
                };

                if (wait_context.acquired) return;
                adaptive_spin = 0;
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub fn release(self: *Self, permits: usize) void {
            @setCold(true);

            std.debug.assert(permits <= MAX);
            var wait_context = WaitContext{
                .semaphore = self,
                .wake_permits = permits,
            };

            var state = atomic.load(&self.state, .Relaxed);
            while (true) {
                if (state & WAITING == 0) {
                    var new_state: usize = undefined;
                    const num_permits = wait_context.wake_permits * PERMIT;
                    if (@addWithOverflow(usize, state, num_permits, &new_state)) {
                        unreachable; // permit overflow
                    }

                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        new_state,
                        .Release,
                        .Relaxed,
                    ) orelse return;
                    continue;
                }

                WaitQueue.wake(
                    @ptrToInt(self),
                    &wake_context,
                );

                if (wake_context.wake_permits == 0) return;
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        const WaitContext = struct {
            semaphore: *Self,
            permits: usize,
            semaphore_permits: ?usize = null,
            acquired: bool = false,

            pub fn onValidate(this: *@This()) ?usize {
                var current_state = atomic.load(&this.semaphore.state, .Relaxed);
                current_state = this.semaphore.tryAcquirePermits(
                    current_state, 
                    this.permits,
                ) orelse {
                    this.acquired = true;
                    return null;
                }

                if (current_state & WAITING == 0) return null;
                return @ptrToInt(this);
            }

            pub fn onBeforeWait(this: @This()) void {}

            pub fn onTimedOut(this: *@This(), waiting: WaitQueue.Waiting) void {
                std.debug.assert(waiting.token.* == @ptrToInt(this));
                const semaphore_permits = this.semaphore_permits orelse return;
                this.semaphore_permits = null;

                const next_token_ptr = waiting.next orelse {
                    _ = atomic.fetchAnd(&this.semaphore.state, ~WAITING, .Relaxed);
                    return;
                };

                const next_context = @intToPtr(*WaitContext, next_token_ptr.*);
                next_context.semaphore_permits = semaphore_permits;
            }
        };

        const WakeContext = struct {
            semaphore: *Self,
            wake_permits: usize,

            pub fn onWake(this: *@This(), waiting: WaitQueue.Waiting) WaitQueue.Waking {
                if (this.wake_permits == 0) {
                    return .Stop;
                }

                const wait_context = @intToPtr(*WaitContext, waiting.token.*);
                var semaphore_permits = wait_context.semaphore_permits orelse 0;
                if (@addWithOverflow(
                    usize, 
                    semaphore_permits, 
                    this.wake_permits, 
                    &semaphore_permits,
                )) {
                    unreachable; // permits overflow
                }

                if (semaphore_permits < wait_context.permits) {
                    wait_context.semaphore_permits = semaphore_permits;
                    this.wake_permits = 0;
                    return .Stop;
                }

                if (waiter.next == null) {
                    _ = atomic.fetchAdd(&this.semaphore.state, ~WAITING, .Relaxed);
                }

                this.wake_permits = semaphore_permits - wait_context.permits;
                wait_context.semaphore_permits = null;
                wait_context.acquired = true;
                return .Wake;
            }

            pub fn onBeforeWake(this: @This()) void {}
        };
    };
}
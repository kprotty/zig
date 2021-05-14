// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

pub fn Mutex(comptime WaitQueue: type) type {
    return extern struct {
        state: State = .unlocked,

        const Self = @This();
        const State = enum(u8) {
            unlocked,
            locked,
            contended,
        };

        const Notify = enum {
            retry,
            acquired,
        };

        pub fn deinit(self: *Self) void {
            std.debug.assert(self.state == .unlocked);
            self.* = undefined;
        }

        pub fn tryAcquire(self: *Self) ?Held {
            return atomic.compareAndSwap(
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Relaxed,
            ) == null;
        }

        pub fn acquire(self: *Self) callconv(.Inline) Held {
            return self.acquireFast(null) catch unreachable;
        }

        pub fn tryAcquireFor(
            self: *Self, 
            duration: std.time.Duration,
        ) error{TimedOut}!Held {
            const timeout = WaitQueue.Instant.now().after(duration);
            const deadline = timeout orelse return error.TimedOut;
            return self.tryAcquireUntil(deadline);
        }

        pub fn tryAcquireUntil(
            self: *Self, 
            deadline: WaitQueue.Instant,
        ) callconv(.Inline) error{TimedOut}!Held {
            return self.acquireFast(deadline);
        }

        fn acquireFast(
            self: *Self, 
            deadline: ?WaitQueue.Instant,
        ) callconv(.Inline) error{TimedOut}!Held {
            if (atomic.tryCompareAndSwap(
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Relaxed,
            )) |failed| {
                try self.acquireSlow(deadline);
            }

            return Held{ .mutex = self };
        }

        fn acquireSlow(
            self: *Self, 
            deadline: ?WaitQueue.Instant,
        ) error{TimedOut}!void {
            @setCold(true);
            
            var adaptive_spin: u8 = 0;
            var new_state = State.locked;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                if (state == .unlocked) {
                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        new_state,
                        .Acquire,
                        .Relaxed,
                    ) orelse return;
                    continue;
                }

                if (state != .contended) {
                    if (adaptive_spin < 5) {
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
                        .contended,
                        .Relaxed,
                        .Relaxed,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                const WaitContext = struct {
                    mutex: *Self,
                    notify_ptr: *Notify,

                    pub fn onValidate(this: @This()) ?usize {
                        const current_state = atomic.load(&this.mutex.state, .Relaxed);
                        if (current_state != .contended) return null;
                        return @ptrToInt(this.notify_ptr);
                    }

                    pub fn onBeforeWait(this: @This()) void {}
                    pub fn onTimedOut(this: @This(), _: WaitQueue.Waiting) void {}
                };

                var notify = Notify.retry;
                WaitQueue.wait(
                    @ptrToInt(self), 
                    deadline,
                    WaitContext{
                        .mutex = self,
                        .notify_ptr = &notify,
                    },
                ) catch |err| switch (err) {
                    error.Invalidated => {},
                    error.TimedOut => return error.TimedOut,
                };

                switch (notify) {
                    .acquired => return,
                    .retry => {
                        adaptive_spin = 0;
                        new_state = .contended;
                        state = atomic.load(&self.state, .Relaxed);
                    },
                }
            }
        }

        pub const Held = extern struct {
            mutex: *Self,

            pub fn release(self: Held) callconv(.Inline) void {
                return self.mutex.releaseFast(false);
            }

            pub fn releaseFair(self: Held) callconv(.Inline) void {
                return self.mutex.releaseFast(true);
            }
        };

        fn releaseFast(self: *Self, comptime be_fair: bool) void {
            if (be_fair) {
                return self.releaseSlow(.acquired);
            }

            switch (atomic.swap(&self.state, .unlocked, .Release)) {
                .unlocked => unreachable, // unlocked an unlocked Mutex
                .locked => {},
                .contended => _ = self.releaseSlow(.retry),
            }
        }

        fn releaseSlow(self: *Self, comptime notify: Notify) void {
            @setCold(true);

            const WakeContext = struct {
                mutex: *Self,
                did_wake: bool = false,

                pub fn onWake(this: *@This(), waiter: WaitQueue.Waiting) WaitQueue.Waking {
                    if (this.did_wake) {
                        return .Stop;
                    }

                    const notify_ptr = @intToPtr(*Notify, waiter.token.*);
                    notify_ptr.* = notify;
                    this.did_wake = true;
                    return .Wake;
                }

                pub fn onBeforeWake(this: @This()) void {
                    if (notify == .Acquired and !this.did_wake) {
                        if (std.debug.runtime_safety) {
                            const state = atomic.load(&this.mutex.state, .Unordered);
                            std.debug.assert(state == .locked);
                        }
                        atomic.store(&this.mutex.state, .unlocked, .Release);
                    }
                }
            };

            WaitQueue.wake(
                @ptrToInt(self),
                &WakeContext{ .mutex = self },
            );
        }
    };
}
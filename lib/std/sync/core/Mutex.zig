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

        const Notify = enum(usize) {
            Retry,
            Acquired,
        };

        pub fn tryAcquire(self: *Self) ?Held {
            return @cmpxchgStrong(
                State,
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Monotonic,
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
            if (@cmpxchgWeak(
                State,
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Monotonic,
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
            var state = @atomicLoad(State, &self.state, .Monotonic);

            while (true) {
                if (state == .unlocked) {
                    state = @cmpxchgWeak(
                        State,
                        &self.state,
                        state,
                        new_state,
                        .Acquire,
                        .Monotonic,
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
                        state = @atomicLoad(State, &self.state, .Monotonic);
                        continue;
                    }

                    if (@cmpxchgWeak(
                        State,
                        &self.state,
                        state,
                        .contended,
                        .Monotonic,
                        .Monotonic,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                const WaitContext = struct {
                    mutex: *Self,

                    pub fn onValidate(this: @This()) ?usize {
                        const current_state = @atomicLoad(State, &this.mutex.state, .Monotonic);
                        if (current_state != .contended) return null;
                        return 0;
                    }

                    pub fn onBeforeWait(this: @This()) void {}
                    pub fn onTimedOut(this: @This(), _: WaitQueue.Waiting) void {}
                };

                const notification = WaitQueue.wait(
                    @ptrToInt(self), 
                    deadline,
                    WaitContext{ .mutex = self },
                ) catch |err| switch (err) {
                    error.Invalidated => Notify.Retry,
                    error.TimedOut => return error.TimedOut,
                };

                switch (@intToEnum(Notify, notification)) {
                    .Acquired => return,
                    .Retry => {
                        adaptive_spin = 0;
                        new_state = .contended;
                        state = @atomicLoad(State, &self.state, .Monotonic);
                        continue;
                    }
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
                return self.releaseSlow(Notify.Acquired);
            }

            switch (@atomicRmw(State, &self.state, .Xchg, .unlocked, .Release)) {
                .unlocked => unreachable, // unlocked an unlocked Mutex
                .locked => {},
                .contended => _ = self.releaseSlow(Notify.Retry),
            }
        }

        fn releaseSlow(self: *Self, comptime notify: Notify) void {
            @setCold(true);

            const WakeContext = struct {
                did_wake: bool = false,
                mutex: *Self,

                pub fn onWake(this: *@This(), _: WaitQueue.Waiting) WaitQueue.Waking {
                    if (self.did_wake) {
                        return .Stop;
                    }

                    self.did_wake = true;
                    return .{ .Wake = @enumToInt(notify) };
                }

                pub fn onBeforeWake(this: @This()) void {
                    if (notify == .Acquired and !self.did_wake) {
                        if (std.debug.runtime_safety) {
                            const state = @atomicLoad(State, &self.mutex.state, .Unordered);
                            std.debug.assert(state == .locked);
                        }
                        @atomicStore(State, &self.mutex.state, .unlocked, .Release);
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
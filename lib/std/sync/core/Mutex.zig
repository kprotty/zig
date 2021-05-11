// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const spinLoopHint = @import("../atomic.zig").spinLoopHint;

pub fn Mutex(
    comptime Futex: type,
    comptime Instant: type,
) type {
    return extern struct {
        state: State = .unlocked,

        const Self = @This();
        const State = enum(u32) {
            unlocked,
            locked,
            contended,
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

        pub fn acquire(self: *Self) Held {
            if (@cmpxchgWeak(
                State,
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Monotonic,
            )) |failed| {
                self.acquireSlow();
            }
            return Held{ .mutex = self };
        }

        fn acquireSlow(self: *Self) void {
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
                            spinLoopHint();
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

                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.contended),
                    null,
                ) catch unreachable;

                adaptive_spin = 0;
                new_state = .contended;
                state = @atomicLoad(State, &self.state, .Monotonic);
            }
        }

        pub const Held = extern struct {
            mutex: *Self,

            pub fn release(self: Held) void {
                switch (@atomicRmw(
                    State, 
                    &self.mutex.state, 
                    .Xchg, 
                    .unlocked, 
                    .Release,
                )) {
                    .unlocked => unreachable, // unlocked an unlocked Mutex
                    .locked => {}, // no waiters so nothing to do
                    .contended => self.releaseSlow(), // need to wake up a waiter
                }
            }

            fn releaseSlow(self: Held) void {
                @setCold(true);

                const ptr = @ptrCast(*const u32, &self.mutex.state);
                Futex.wake(ptr, 1);
            }
        };
    };
}
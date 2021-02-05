// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn Lock(comptime parking_lot: type) type {
    return struct {
        state: State = .unlocked,

        const Self = @This();
        const Futex = parking_lot.WaitFutex;
        const State = enum(u32) {
            unlocked,
            locked,
            contended,
        };

        pub fn tryAcquire(self: *Self) ?Held {
            if (atomic.compareAndSwap(
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Relaxed,
            )) |failed| {
                return null;
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .lock = self };
        }

        pub fn acquire(self: *Self) Held {
            const state = atomic.swap(&self.state, .locked, .Acquire);
            if (state != .unlocked) {
                self.acquireSlow(state);
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .lock = self };
        }

        fn acquireSlow(self: *Self, current_state: State) void {
            @setCold(true);
            
            var adaptive_spin: usize = 0;
            var new_state = current_state;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                while (true) {
                    switch (state) {
                        .unlocked => _ = atomic.compareAndSwap(
                            &self.state,
                            .unlocked,
                            new_state,
                            .Acquire,
                            .Relaxed,
                        ) orelse return,
                        .locked => {},
                        .contended => break,
                    }

                    if (Futex.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                        state = atomic.load(&self.state, .Relaxed);
                    } else {
                        break;
                    }
                }

                new_state = .contended;
                if (state != .contended) {
                    state = atomic.swap(&self.state, new_state, .Acquire);
                    if (state == .unlocked) {
                        return;
                    }
                }

                // Wait on the Lock while its contended and try to acquire it again when we wake up.
                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.contended),
                    null,
                ) catch unreachable;
                adaptive_spin = 0;
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub const Held = struct {
            lock: *Self,

            pub fn release(self: Held) void {
                return self.lock.release();
            }
        };

        fn release(self: *Self) void {
            switch (atomic.swap(&self.state, .unlocked, .Release)) {
                .unlocked => unreachable,
                .locked => {},
                .contended => self.releaseSlow(),
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);
            Futex.wake(@ptrCast(*const u32, &self.state));
        }
    };
}
// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");
const ParkingLot = @import("../primitives/ParkingLot.zig").ParkingLot;

const builtin = std.builtin;

pub fn GenericFutex(comptime ParkingLotConfig: type) type {
    return struct {
        const parking_lot = ParkingLot(ParkingLotConfig);
        
        pub const Lock = GenericFutexLock(@This());

        pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
            const Parker = struct {
                wait_ptr: *const u32,
                wait_expect: u32,

                pub fn onValidate(self: @This()) ?parking_lot.Token {
                    if (atomic.load(self.wait_ptr, .SeqCst) == self.wait_expect) {
                        return 0;
                    } else {
                        return null;
                    }
                }

                pub fn onBeforeWait(self: @This()) void {
                    // no-op
                }

                pub fn onCancel(self: @This(), unparked: parking_lot.Unparked) void {
                    // no-op
                }
            };

            _ = parking_lot.park(
                @ptrToInt(ptr) >> @sizeOf(u32),
                @as(?ParkingLotConfig.Event.Cancellation, timeout),
                Parker{
                    .wait_ptr = ptr,
                    .wait_expect = expected,
                },
            ) catch |err| switch (err) {
                error.Invalidated => {},
                error.Cancelled => return error.TimedOut,
            };
        }

        pub fn wake(ptr: *const u32) void {
            const Unparker = struct {
                pub fn onUnpark(self: @This(), unparked: parking_lot.Unparked) parking_lot.Token {
                    return 0;
                }
            };

            parking_lot.unparkOne(
                @ptrToInt(ptr) >> @sizeOf(u32),
                Unparker{},
            );
        }

        pub fn yield(iteration: usize) bool {
            return ParkingLotConfig.Event.yield(iteration);
        }
    };
}

pub fn GenericFutexLock(comptime Futex: type) {
    return struct {
        state: State = .unlocked,

        const Self = @This();
        const State = enum(u32) {
            unlocked,
            locked,
            contended,
        };

        pub fn acquire(self: *Self) void {
            const state = atomic.swap(&self.state, .locked, .Acquire);
            if (state != .unlocked) {
                self.acquireSlow(state);
            }
        }

        fn acquireSlow(self: *Self, current_state: State) void {
            @setCold(true);
            
            var adaptive_spin: usize = 0;
            var new_state = current_state;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                // If the lock is unlocked, try to acquire it.
                // If we fail, explicitely fall through to either Futex.wait() or Event.yield().
                if (state == .unlocked) {
                    state = atomic.compareAndSwap(
                        &self.state,
                        .unlocked,
                        new_state,
                        .Acquire,
                        .Relaxed,
                    ) orelse return;
                }

                if (state != .contended) {
                    // Try to spin on the lock when it has no waiters (!= .contended).
                    if (Event.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    // If we can no longer spin, then mark that we're about to wait.
                    new_state = .contended;
                    if (atomic.swap(&self.state, .contended, .Acquire) == .unlocked) {
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

        pub fn release(self: *Self) void {
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

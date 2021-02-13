// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const testing = std.testing;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn Mutex(comptime parking_lot: type) type {
    if (@hasDecl(parking_lot.backend, "CoreMutex")) {
        return parking_lot.backend.CoreMutex;
    }

    return struct {
        state: u8 = UNLOCKED,

        const UNLOCKED: u8 = 0;
        const LOCKED: u8 = 1;
        const PARKED: u8 = 2;

        const TOKEN_RETRY: parking_lot.Token = 0;
        const TOKEN_ACQUIRE: parking_lot.Token = 1;

        const Self = @This();

        pub const Cancellation = parking_lot.Cancellation;

        pub fn deinit(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBeforeForgetAll(@ptrToInt(self));
            }

            self.* = undefined;
        }

        pub fn tryAcquire(self: *Self) ?Held {
            const acquired = switch (builtin.arch) {
                .i386, .x86_64 => atomic.bitSet(
                    &self.state,
                    @ctz(std.math.Log2Int(u8), LOCKED),
                    .Acquire,
                ) == 0,
                else => blk: {
                    var state: u8 = UNLOCKED;
                    while (true) {
                        if (state & LOCKED != 0) break :blk false;
                        state = atomic.tryCompareAndSwap(
                            &self.state,
                            state,
                            state | LOCKED,
                            .Acquire,
                            .Relaxed,
                        ) orelse break :blk true;
                    }
                },
            };

            if (!acquired) {
                return null;
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .mutex = self };
        }

        pub inline fn acquire(self: *Self) Held {
            return self.acquireFast(null) catch unreachable;
        }

        pub inline fn tryAcquireWith(self: *Self, cancellation: Cancellation) error{Cancelled}!Held {
            return self.acquireFast(cancellation);
        }

        fn acquireFast(self: *Self, cancellation: ?Cancellation) error{Cancelled}!Held {
            const acquired = switch (builtin.arch) {
                .i386, .x86_64 => atomic.bitSet(
                    &self.state,
                    @ctz(std.math.Log2Int(u8), LOCKED),
                    .Acquire,
                ) == 0,
                else => atomic.tryCompareAndSwap(
                    &self.state,
                    UNLOCKED,
                    LOCKED,
                    .Acquire,
                    .Relaxed,
                ) == null,
            };

            if (!acquired) {
                try self.acquireSlow(cancellation);
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .mutex = self };
        }

        fn acquireSlow(self: *Self, _cancellation: ?Cancellation) error{Cancelled}!void {
            @setCold(true);

            var adaptive_spin: usize = 0;
            var cancellation = _cancellation;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                if (state & LOCKED == 0) {
                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state | LOCKED,
                        .Acquire,
                        .Relaxed,
                    ) orelse return;
                    atomic.spinLoopHint();
                    continue;
                }

                if (state & PARKED == 0) {
                    if (parking_lot.Event.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state | PARKED,
                        .Relaxed,
                        .Relaxed,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                const Parker = struct {
                    mutex: *Self,

                    pub fn onValidate(parker: @This()) ?parking_lot.Token {
                        const mutex_state = atomic.load(&parker.mutex.state, .Relaxed);
                        if (mutex_state == LOCKED | PARKED) {
                            return 0;
                        } else {
                            return null;
                        }
                    }

                    pub fn onBeforeWait(parker: @This()) void {
                        // no-op
                    }

                    pub fn onCancel(parker: @This(), unparked: parking_lot.Unparked) void {
                        if (!unparked.has_more) {
                            _ = atomic.fetchAnd(&parker.mutex.state, ~PARKED, .Relaxed);
                        }
                    }
                };

                const unpark_token = parking_lot.park(
                    @ptrToInt(self),
                    if (cancellation) |*cc| cc else null,
                    Parker{ .mutex = self },
                ) catch |err| switch (err) {
                    error.Invalidated => TOKEN_RETRY,
                    error.Cancelled => return error.Cancelled,
                };

                switch (unpark_token) {
                    TOKEN_RETRY => {
                        adaptive_spin = 0;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    },
                    TOKEN_ACQUIRE => return,
                    else => unreachable,
                }
            }
        }

        pub const Held = struct {
            mutex: *Self,

            pub inline fn release(self: Held) void {
                return self.mutex.releaseFast(false);
            }

            pub inline fn releaseFair(self: Held) void {
                return self.mutex.releaseFast(true);
            }
        };

        fn releaseFast(self: *Self, force_fair: bool) void {
            if (helgrind) |hg| {
                hg.annotateHappensBefore(@ptrToInt(self));
            }

            if (atomic.compareAndSwap(
                &self.state,
                LOCKED,
                UNLOCKED,
                .Release,
                .Relaxed,
            )) |failed| {
                self.releaseSlow(force_fair);
            }
        }

        fn releaseSlow(self: *Self, force_fair: bool) void {
            @setCold(true);

            const Unparker = struct {
                mutex: *Self,
                be_fair: bool,

                pub fn onUnpark(unparker: @This(), unparked: parking_lot.Unparked) parking_lot.Token {
                    const mutex = unparker.mutex;
                    const be_fair = unparker.be_fair or unparked.be_fair;

                    if (unparked.token != null and be_fair) {
                        if (!unparked.has_more) {
                            atomic.store(&mutex.state, LOCKED, .Relaxed);
                        }
                        return TOKEN_ACQUIRE;
                    }

                    const new_state = if (unparked.has_more) PARKED else UNLOCKED;
                    atomic.store(&mutex.state, new_state, .Release);
                    return TOKEN_RETRY;
                }
            };

            parking_lot.unparkOne(
                @ptrToInt(self),
                Unparker{
                    .mutex = self,
                    .be_fair = force_fair,
                },
            );
        }
    };
}

test "Mutex - Serial" {
    try testMutex(
        Mutex(std.sync.core.with(std.sync.backend.serial).parking_lot),
        null,
        .{},
    );
}

test "Mutex - Spin" {
    const parking_lot = std.sync.core.with(std.sync.backend.spin).parking_lot;

    var cancellations: [5]parking_lot.Cancellation = undefined;
    for (cancellations) |*cc, index| {
        cc.* = .{
            .context = index,
            .isCancelledFn = struct {
                fn isCancelled(self: *parking_lot.Cancellation) bool {
                    if (self.context == 0) return true;
                    self.context -= 1;
                    return false;
                }
            }.isCancelled,
        };
    }

    try testMutex(
        Mutex(parking_lot),
        std.Thread,
        cancellations,
    );
}

test "Mutex - OS" {
    const parking_lot = std.sync.core.with(std.sync.backend.os).parking_lot;

    const delay = 1 * std.time.ns_per_ms;
    const cancellations = [_]parking_lot.Cancellation{
        .{ .Duration = delay },
        .{ .Deadline = parking_lot.Cancellation.now() + delay },
    };

    try testMutex(
        Mutex(parking_lot),
        std.Thread,
        cancellations,
    );
}

fn testMutex(
    comptime TestMutex: type,
    comptime TestThread: ?type,
    cancellations: anytype,
) !void {
    {
        var mutex = TestMutex{};
        defer if (@hasDecl(TestMutex, "deinit")) {
            mutex.deinit();
        };

        var held = mutex.tryAcquire() orelse unreachable;
        testing.expectEqual(mutex.tryAcquire(), null);
        held.release();

        held = mutex.acquire();
        defer held.release();

        for (cancellations) |cancellation| {
            testing.expectError(error.Cancelled, mutex.tryAcquireWith(cancellation));
        }
    }

    try @import("./Lock.zig").testLock(TestMutex, TestThread);
}

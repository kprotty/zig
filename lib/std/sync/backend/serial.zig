// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const safety = std.debug.runtime_safety;

inline fn deadlock() noreturn {
    @panic("deadlock detected");
}

pub const CoreParkingLot = struct {
    pub const backend = @This();

    pub const Lock = CoreLock;
    pub const Event = CoreEvent;
    pub const Timeout = CoreTimeout;
    pub const bucket_count = CoreBucketCount;
    pub const Cancellation = std.sync.backend.os.Cancellation;

    // Token needs to be the same as ParkingLot.Token
    pub const Token = usize;

    // Waiter needs to have the same interface as ParkingLot.Token
    // but its implementation isn't required as in serial, there are no waiters.
    pub const Waiter = struct {
        pub fn getToken(self: Waiter) Token {
            return undefined;
        }

        pub fn hasMore(self: Waiter) bool {
            return undefined;
        }

        pub fn beFair(self: Waiter) bool {
            return undefined;
        }
    };

    // Filtered needs to be the same as ParkingLot.Filtered
    pub const Filtered = union(enum) {
        Stop,
        Skip,
        Unpark: Token,
    };

    // Requeued needs to be the same as ParkingLot.Requeued
    pub const Requeued = struct {
        unpark: usize = 0,
        requeue: usize = 0,
    };

    // Unparked needs to be the same as ParkingLot.Unparked
    pub const Unparked = struct {
        token: ?Token = null,
        has_more: bool = false,
        be_fair: bool = false,
    };

    pub fn park(
        address: usize,
        cancellation: ?*Cancellation,
        callback: anytype,
    ) error{ Invalidated, Cancelled }!Token {
        const token = callback.onValidate() orelse return error.Invalidated;
        const cc = cancellation orelse deadlock();
        callback.onBeforeWait();
        std.time.sleep(cc.nanoseconds() orelse 0);
        callback.onCancel(Unparked{ .token = token });
        return error.Cancelled;
    }

    pub fn unparkAll(
        address: usize,
        token: Token,
    ) void {
        // no-op, theres no other threads to wake
    }

    pub fn unparkOne(
        address: usize,
        callback: anytype,
    ) void {
        const unpark_token: Token = callback.onUnpark(Unparked{});
    }

    pub fn unparkFilter(
        address: usize,
        callback: anytype,
    ) void {
        callback.onBeforeWake();
    }

    pub fn unparkRequeue(
        address: usize,
        requeue_address: usize,
        callback: anytype,
    ) void {
        const requeued = callback.onRequeue() orelse return;
        callback.onBeforeWake(Requeued{});
    }
};

pub const CoreFutex = struct {
    pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*CoreParkingLot.Cancellation) error{Cancelled}!void {
        if (ptr.* != expected) return;
        const cc = cancellation orelse deadlock();
        std.time.sleep(cc.nanoseconds() orelse 0);
        return error.Cancelled;
    }

    pub fn notifyOne(ptr: *const u32) void {
        // no-op: no threads to wake up
    }

    pub fn notifyAll(ptr: *const u32) void {
        // no-op: no threads to wake up
    }

    pub fn yield(iteration: usize) bool {
        return false;
    }
};

pub const CoreLock = CoreMutex;
pub const CoreMutex = struct {
    is_locked: @TypeOf(lock_state) = lock_state,

    const Self = @This();
    const lock_state = if (safety) false else {};

    pub fn deinit(self: *Self) void {
        if (safety and self.is_locked) unreachable;
        self.* = undefined;
    }

    pub fn tryAcquire(self: *Self) ?Held {
        if (safety and self.is_locked) return null;
        return Held{ .mutex = self };
    }

    pub fn acquire(self: *Self) Held {
        return self.tryAcquire() orelse deadlock();
    }

    pub fn acquireWith(self: *Self, cancellation: CoreParkingLot.Cancellation) error{Cancelled}!Held {
        return self.tryAcquire() orelse {
            std.time.sleep(cancellation.nanoseconds() orelse 0);
            return error.Cancelled;
        };
    }

    pub const Held = struct {
        mutex: *Self,

        pub fn release(self: Held) void {
            return self.releaseFair();
        }

        pub fn releaseFair(self: Held) void {
            if (safety) {
                if (!self.mutex.is_locked) unreachable;
                self.mutex.is_locked = false;
            }
        }
    };
};

pub const CoreOnce = struct {
    is_called: bool = false,

    const Self = @This();

    pub fn call(self: *Self, initFn: anytype) void {
        if (self.is_called) return;
        const result = initFn();
        self.is_called = true;
    }
};

pub const CoreEvent = CoreResetEvent;
pub const CoreResetEvent = struct {
    is_set: bool = false,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.* = undefined;
    }

    pub fn isSet(self: *const Self) bool {
        return self.is_set;
    }

    pub fn reset(self: *Self) void {
        self.is_set = false;
    }

    pub fn set(self: *Self) void {
        self.is_set = true;
    }

    pub fn wait(self: *Self) void {
        if (self.is_set) return;
        deadlock();
    }

    pub fn waitWith(self: *Self, cancellation: CoreParkingLot.Cancellation) error{Cancelled}!void {
        if (self.is_set) return;
        std.time.sleep(cancellation.nanoseconds() orelse 0);
        return error.Cancelled;
    }

    pub fn yield(iteration: usize) bool {
        return CoreFutex.yield(iteration);
    }
};

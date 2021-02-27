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

pub fn ResetEvent(comptime Futex: type) type {
    return extern struct {
        state: State = .empty,

        const Self = @This();
        const State = enum(u32) {
            empty,
            waiting,
            notified,
        };

        pub const Dummy = DebugResetEvent;

        pub fn init(is_set: bool) Self {
            return .{ .state = if (is_set) .notified else .empty };
        }

        pub fn deinit(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBeforeForgetAll(@ptrToInt(self));
            }

            self.* = undefined;
        }

        pub fn isSet(self: *const Self) bool {
            const state = atomic.load(&self.state, .SeqCst);
            const is_set = state == .notified;

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return is_set;
        }

        pub fn reset(self: *Self) void {
            atomic.store(&self.state, .empty, .Relaxed);
        }

        pub fn tryWait(self: *Self) void {
            return self.isSet();
        }

        pub fn wait(self: *Self) callconv(.Inline) void {
            self.waitInner(null) catch unreachable;
        }

        pub fn tryWaitFor(self: *Self, duration: u64) callconv(.Inline) error{TimedOut}!void {
            return self.tryWaitUntil(Futex.now() + duration);
        }

        pub fn tryWaitUntil(self: *Self, deadline: u64) callconv(.Inline) error{TimedOut}!void {
            return self.waitInner(deadline);
        }

        fn waitInner(self: *Self, deadline: ?u64) error{TimedOut}!void {
            while (true) {
                const state = atomic.load(&self.state, .Acquire);
                if (state == .notified) {
                    break;
                }

                if (state == .empty) {
                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        .empty,
                        .waiting,
                        .Acquire,
                        .Acquire,
                    )) |updated| {
                        atomic.spinLoopHint();
                        continue;
                    }
                }

                try Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.waiting),
                    deadline,
                );
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }
        }

        pub fn set(self: *Self) void {
            var state = atomic.load(&self.state, .Relaxed);
            if (state == .notified) {
                return;
            }

            if (helgrind) |hg| {
                hg.annotateHappensBefore(@ptrToInt(self));
            }

            switch (atomic.swap(&self.state, .notified, .Release)) {
                .empty => return,
                .waiting => {},
                .notified => return,
            }

            const ptr = @ptrCast(*const u32, &self.state);
            Futex.wake(ptr, std.math.maxInt(u32));
        }
    };
}

pub const DebugResetEvent = extern struct {
    is_set: bool = false,

    const Self = @This();

    pub fn init(is_set: bool) Self {
        return .{ .is_set = is_set };
    }

    pub fn deinit(self: *Self) void {
        self.* = undefined;
    }

    pub fn isSet(self: *const Self) bool {
        return self.is_set;
    }

    pub fn reset(self: *Self) void {
        self.is_set = false;
    }

    pub fn wait(self: *Self) void {
        if (!self.is_set) {
            @panic("deadlock detected");
        }
    }

    pub fn tryWaitFor(self: *Self, duration: u64) error{TimedOut}!void {
        if (!self.is_set) {
            std.time.sleep(duration);
            return error.TimedOut;
        }
    }

    pub fn tryWaitUntil(self: *Self, deadline: u64) error{TimedOut}!void {
        if (!self.is_set) {
            const now = std.time.now();
            if (now < deadline) {
                std.time.sleep(deadline - now);
            }
            return error.TimedOut;
        }
    }

    pub fn set(self: *Self) void {
        self.is_set = true;
    }
};

test "ResetEvent - Debug" {
    try testResetEvent(DebugResetEvent, null);
}

test "ResetEvent - Spin" {
    try testResetEvent(ResetEvent(std.sync.futex.spin), std.Thread);
}

test "ResetEvent - Os" {
    try testResetEvent(ResetEvent(std.sync.futex.os), std.Thread);
}

test "ResetEvent - Evented" {
    if (!std.io.is_async or std.builtin.single_threaded) return error.SkipZigTest;
    try testResetEvent(
        ResetEvent(std.sync.futex.event),
        @import("../futex/event.zig").TestThread,
    );
}

fn testResetEvent(
    comptime TestResetEvent: type,
    comptime TestThread: ?type,
) !void {
    {
        var event = TestResetEvent{};
        defer event.deinit();
        testing.expect(!event.isSet());

        const delay = 1 * std.time.ns_per_ms;
        testing.expectError(error.TimedOut, event.tryWaitFor(delay));
        testing.expectError(error.TimedOut, event.tryWaitUntil(std.time.now() + delay));

        event.set();
        testing.expect(event.isSet());

        event.wait();
        try event.tryWaitFor(delay);
        try event.tryWaitUntil(std.time.now() + delay);

        event.reset();
        testing.expect(!event.isSet());
        testing.expectError(error.TimedOut, event.tryWaitFor(delay));
        testing.expectError(error.TimedOut, event.tryWaitUntil(std.time.now() + delay));
    }

    const Thread = TestThread orelse return;

    const PingPong = struct {
        value: usize = 0,
        ping_event: TestResetEvent = .{},
        pong_event: TestResetEvent = .{},

        const Self = @This();
        const round_trips = 3;

        fn run(self: *Self) !void {
            const pong = try Thread.spawn(self, runPong);
            self.runPing();
            pong.wait();

            self.ping_event.deinit();
            self.pong_event.deinit();
        }

        fn runPing(self: *Self) void {
            var value = atomic.load(&self.value, .SeqCst);
            testing.expectEqual(value, 0);

            var rt: usize = round_trips;
            while (rt > 0) : (rt -= 1) {
                value += 1;
                atomic.store(&self.value, value, .SeqCst);
                self.ping_event.set();

                self.pong_event.wait();
                self.pong_event.reset();
                const new_value = atomic.load(&self.value, .SeqCst);

                testing.expectEqual(new_value, value + 1);
                value = new_value;
            }
        }

        fn runPong(self: *Self) void {
            var value: usize = 0;
            testing.expectEqual(value, 0);

            var rt: usize = round_trips;
            while (rt > 0) : (rt -= 1) {
                self.ping_event.wait();
                self.ping_event.reset();
                const new_value = atomic.load(&self.value, .SeqCst);

                testing.expectEqual(new_value, value + 1);
                value = new_value;

                value += 1;
                atomic.store(&self.value, value, .SeqCst);
                self.pong_event.set();
            }
        }
    };

    var ping_pong = PingPong{};
    try ping_pong.run();
}

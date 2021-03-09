// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const atomic = @import("./atomic.zig");

const builtin = std.builtin;
const testing = std.testing;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub const os = @import("./futex/os.zig");
pub const spin = @import("./futex/spin.zig");
pub const event = @import("./futex/event.zig");
pub const Generic = @import("./futex/generic.zig").Futex;

test "futex" {
    const generic = struct {
        fn forFutex(comptime Futex: type) type {
            return Generic(struct {
                state: State,

                const Self = @This();
                const State = enum(u32) { unset, set };
                pub const Lock = @import("./primitives/Mutex.zig").Mutex(Futex);

                pub fn init(self: *Self) void {
                    self.state = .unset;
                }

                pub fn deinit(self: *Self) void {
                    if (helgrind) |hg| {
                        hg.annotateHappensBeforeForgetAll(@ptrToInt(self));
                    }

                    self.* = undefined;
                }

                pub fn wait(self: *Self, deadline: ?u64) error{TimedOut}!void {
                    defer if (helgrind) |hg| {
                        hg.annotateHappensAfter(@ptrToInt(self));
                    };

                    while (atomic.load(&self.state, .SeqCst) == .unset) {
                        try Futex.wait(
                            @ptrCast(*const u32, &self.state),
                            @enumToInt(State.unset),
                            deadline,
                        );
                    }
                }

                pub fn set(self: *Self) void {
                    if (helgrind) |hg| {
                        hg.annotateHappensBefore(@ptrToInt(self));
                    }

                    atomic.store(&self.state, .set, .SeqCst);
                    Futex.wake(@ptrCast(*const u32, &self.state), @as(u32, 1));
                }

                pub fn reset(self: *Self) void {
                    self.state = .unset;
                }
            });
        }
    };

    inline for (.{
        os,
        spin,
        event,
        generic.forFutex(os),
        generic.forFutex(spin),
    }) |futex| {
        {
            // Simple wait/wake
            const Context = struct {
                state: State = .unset,
                const State = enum(u32) { unset, set };

                fn waker(ctx: *@This()) !void {
                    std.time.sleep(std.time.ns_per_ms * 2);
                    atomic.store(&ctx.state, .set, .SeqCst);
                    Futex.wake(@ptrCast(*const u32, &ctx.state), @as(u32, 1));
                }

                fn waiter(ctx: *@This()) !void {
                    while (atomic.load(&ctx.state, .SeqCst) == .unset) {
                        futex.wait(@ptrCast(*const u32, &ctx.state), @enumToInt(State.unset), null) catch unreachable;
                    }
                }
            };

            var ctx = Context{};
            var twait = try std.Thread.spawn(&ctx, Context.waiter);
            var twake = try std.Thread.spawn(&ctx, Context.waker);

            twait.wait();
            twake.wait();
        }

        {
            // Multiple wake
            const waiters = 8;

            const Context = struct {
                state: State = .unset,
                const State = enum(u32) { unset, set };

                fn waker(ctx: *@This()) !void {
                    std.time.sleep(std.time.ns_per_ms * 2);
                    atomic.store(&ctx.state, .set, .SeqCst);
                    Futex.wake(@ptrCast(*const u32, &ctx.state), @as(u32, waiters));
                }

                fn waiter(ctx: *@This()) !void {
                    while (atomic.load(&ctx.state, .SeqCst) == .unset) {
                        futex.wait(@ptrCast(*const u32, &ctx.state), @enumToInt(State.unset), null) catch unreachable;
                    }
                }
            };

            var ctx = Context{};
            var twaiters: [waiters]*std.Thread = undefined;
            for (twaiters) |*waiter| {
                waiter.* = try std.Thread.spawn(&ctx, Context.waiter);
            }
            var twake = try std.Thread.spawn(&ctx, Context.waker);

            twake.wait();
            for (twaiters) |waiter| {
                waiter.wait();
            }
        }

        {
            // Timeout
            const Context = struct {
                state: State = .unset,
                const State = enum(u32) { unset, set };

                const duration = std.time.ns_per_ms * 2;

                fn slowWaker(ctx: *@This()) !void {
                    std.time.sleep(duration + 1);
                    atomic.store(&ctx.state, .set, .SeqCst);
                    Futex.wake(@ptrCast(*const u32, &ctx.state), @as(u32, 1));
                }

                fn waiter(ctx: *@This()) !void {
                    while (atomic.load(&ctx.state, .SeqCst) == .unset) {
                        futex.wait(@ptrCast(*const u32, &ctx.state), @enumToInt(State.unset), duration) catch return;
                    }
                    unreachable;
                }
            };

            var ctx = Context{};
            var twait = try std.Thread.spawn(&ctx, Context.waiter);
            var twake = try std.Thread.spawn(&ctx, Context.slowWaker);

            twait.wait();
            twake.wait();
        }
    }
}

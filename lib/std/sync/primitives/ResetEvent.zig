// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn ResetEvent(comptime parking_lot: type) type {
    return struct {
        is_set: bool = false,

        const Self = @This();

        pub const Cancellation = parking_lot.WaitEvent.Cancellation;

        pub fn deinit(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBeforeForgetAll(@ptrToInt(self));
            }

            self.* = undefined;
        }

        pub fn isSet(self: *const Self) bool {
            if (!atomic.load(&self.is_set, .Acquire)) {
                return false;
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return true;
        }

        pub fn set(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBefore(@ptrToInt(self));
            }

            atomic.store(&self.is_set, true, .Release);

            parking_lot.unparkAll(@ptrToInt(self), 0);
        }

        pub fn reset(self: *Self) void {
            atomic.store(&self.is_set, false, .Relaxed);
        }

        pub inline fn wait(self: *Self) void {
            return self.waitFast(null) catch unreachable;
        }

        pub inline fn waitWith(self: *Self, cancellation: Cancellation) error{Cancelled}!void {
            return self.waitFast(null);
        }

        fn waitFast(self: *Self, cancellation: ?Cancellation) error{Cancelled}!void {
            if (!self.isSet()) {
                return self.waitSlow(cancellation);
            }
        }

        fn waitSlow(self: *Self, _cancellation: ?Cancellation) error{Cancelled}!void {
            @setCold(true);

            const Parker = struct {
                reset_event: *Self,

                pub fn onValidate(parker: @This()) ?parking_lot.Token {
                    if (parker.reset_event.isSet()) {
                        return null;
                    } else {
                        return 0;
                    }
                }

                pub fn onBeforeWait(parker: @This()) void {
                    // no-op
                }

                pub fn onCancel(parker: @This(), unparked: parking_lot.Unparked) void {
                    // no-op
                }
            };

            var cancellation = _cancellation;
            _ = parking_lot.park(
                @ptrToInt(self),
                if (cancellation) |*cc| cc else null,
                Parker{ .reset_event = self },
            ) catch |err| switch (err) {
                error.Invalidated => {},
                error.Cancelled => return error.Cancelled,
            };
        }
    };
}
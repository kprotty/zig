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

pub fn Futex(comptime parking_lot: type) type {
    if (@hasDecl(parking_lot.backend, "CoreFutex")) {
        return parking_lot.backend.CoreFutex;
    }

    return struct {
        pub const Cancellation = parking_lot.Cancellation;

        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
            const Parker = struct {
                wait_ptr: *const u32,
                wait_expected: u32,

                pub fn onValidate(parker: @This()) ?parking_lot.Token {
                    if (atomic.load(parker.wait_ptr, .SeqCst) == parker.wait_expected) {
                        return 0;
                    } else {
                        return null;
                    }
                }

                pub fn onBeforeWait(parker: @This()) void {
                    // no-op
                }

                pub fn onCancel(parker: @This(), unparked: parking_lot.Unparked) void {
                    // no-op
                }
            };

            _ = parking_lot.park(
                @ptrToInt(ptr) >> @sizeOf(@TypeOf(ptr.*)),
                cancellation,
                Parker{
                    .wait_ptr = ptr,
                    .wait_expected = expected,
                },
            ) catch |err| switch (err) {
                error.Invalidated => {},
                error.Cancelled => return error.Cancelled,
            };
        }

        pub fn notifyOne(ptr: *const u32) void {
            const Unparker = struct {
                pub fn onUnpark(unparker: @This(), unparked: parking_lot.Unparked) parking_lot.Token {
                    return 0;
                }
            };

            parking_lot.unparkOne(
                @ptrToInt(ptr) >> @sizeOf(@TypeOf(ptr.*)),
                Unparker{},
            );
        }

        pub fn notifyAll(ptr: *const u32) void {
            parking_lot.unparkAll(
                @ptrToInt(ptr) >> @sizeOf(@TypeOf(ptr.*)),
                @as(parking_lot.Token, 0),
            );
        }

        pub fn yield(iteration: usize) bool {
            return parking_lot.Event.yield(iteration);
        }
    };
}

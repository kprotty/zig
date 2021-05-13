// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const Duration = std.time.Duration;
const single_threaded = std.builtin.single_threaded;

//! A Futex provides a method to block and unblock OS threads by
//! waiting for either a pointer to change value or another thread to send a notification.
//!
//! It works by forming a "wait queue" using the given pointer address and
//! checking the pointer value atomically when enqueuing to not miss notifications.
//!
//! The API is conceptually similar to `std.os.linux.futex_wait` and `std.os.linux.futex_wake`.
//! See the `wait` and `wake` methods for more information.

pub fn Futex(comptime WaitQueue: type) type {
    return struct {
        /// Blocks the calling thread while the value at `ptr` is equal to the value of `expected`,
        /// or until it is notified by a matching `wake()`. Spurious wakeups are also allowed.
        ///
        /// The comparison of the `ptr` value to `expected` is done atomically and totally-ordered
        /// with respect to other atomic operations operating on the `ptr` memory location.
        pub fn wait(ptr: anytype, expected: @TypeOf(ptr.*)) void {
            if (single_threaded) {
                if (atomic.load(ptr, .SeqCst) != expected) return;
                @panic("deadlock detected");
            }

            return tryWait(ptr, expected, null) catch unreachable;
        }

        /// Blocks the calling thread while the value at `ptr` is equal to the value of `expected`,
        /// or until it is notified by a matching `wake()`. Spurious wakeups are also allowed.
        ///
        /// A `duration` value is provided which acts as a hint for the maximum amount of time 
        /// the calling thread can be blocked waiting for the `ptr` to change from `expected`.
        /// If the timeout delay is reached, the function returns `error.TimedOut`.
        ///
        /// The comparison of the `ptr` value to `expected` is done atomically and totally-ordered
        /// with respect to other atomic operations operating on the `ptr` memory location.
        pub fn tryWaitFor(
            ptr: anytype, 
            expected: @TypeOf(ptr.*), 
            duration: Duration,
        ) error{TimedOut}!void {
            if (duration.asNanos() == 0) {
                if (atomic.load(ptr, .SeqCst) != expected) return;
                return error.TimedOut;
            }

            var deadline = WaitQueue.WaitInstant.now();
            deadline = deadline.after(duration);
            return tryWaitUntil(ptr, expected, deadline);
        }

        /// Blocks the calling thread while the value at `ptr` is equal to the value of `expected`,
        /// or until it is notified by a matching `wake()`. Spurious wakeups are also allowed.
        ///
        /// A `deadline` value is provided which acts as a hint for when the calling thread 
        /// has to give up blocking waiting for the `ptr` to change from `expected`.
        /// If the deadline is reached or is passed, the function returns `error.TimedOut`.
        ///
        /// The comparison of the `ptr` value to `expected` is done atomically and totally-ordered
        /// with respect to other atomic operations operating on the `ptr` memory location.
        pub fn tryWaitUntil(
            ptr: anytype, 
            expected: @TypeOf(ptr.*), 
            deadline: WaitQueue.WaitInstant,
        ) error{TimedOut}!void {
            return tryWait(ptr, expected, deadline);
        }

        fn tryWait(
            ptr: anytype, 
            expected: @TypeOf(ptr.*), 
            deadline: ?WaitQueue.WaitInstant,
        ) error{TimedOut}!void {
            const Type = @TypeOf(ptr.*);            
            const WaitContext = struct {
                pointer: *Type,
                compare: Type,

                pub fn onValidate(this: @This()) ?usize {
                    const value = atomic.load(this.pointer, .SeqCst);
                    if (value != this.compare) return null;
                    return 0;
                }

                pub fn onBeforeWait(this: @This()) void {}
                pub fn onTimedOut(this: @This(), _: WaitQueue.Waiting) void {}
            };

            return WaitQueue.wait(
                @ptrToInt(ptr),
                deadline,
                WaitContext{
                    .pointer = ptr,
                    .compare = expected,
                },
            );
        }

        /// Unblocks a set of threads waiting on the `ptr` to be changed by a matching `wait()`.
        /// `waiters` is used as a hint for how many waiting threads to wake up.
        /// Note that blocked threads can still wake up spuriously by timeout or other internal events.
        pub fn wake(ptr: anytype, waiters: usize) void {
            if (single_threaded or waiters == 0) {
                return;
            }

            const WakeContext = struct {
                notifications: usize,

                pub fn onWake(this: *@This(), _: WaitQueue.Waiting) WaitQueue.Waking {
                    if (self.notifications == 0) {
                        return .Stop;
                    }

                    self.notifications -= 1;
                    return .{ .Wake = 0 };
                }

                pub fn onBeforeWake(this: @This()) void {}
            };

            return WaitQueue.wake(
                @ptrToInt(ptr),
                &WakeContext{ .notifications = waiters },
            );
        }
    };
}
// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! A Futex provides a method to block and unblock OS threads by
//! waiting for either a pointer to change value or another thread to send a notification.
//!
//! It works by forming a "wait queue" using the given pointer address and
//! checking the pointer value atomically when enqueuing to not miss notifications.
//!
//! The API is conceptually similar to `std.os.linux.futex_wait` and `std.os.linux.futex_wake`.
//! See the `wait` and `wake` methods for more information.

const std = @import("../std.zig");

/// Blocks the calling thread while the value at `ptr` is equal to the value of `expected`,
/// or until it is notified by a matching `wake()`. Spurious wakeups are also allowed.
///
/// A `timeout` value in nanoseconds can be provided which acts as a hint for
/// the maximum amount of time the calling thread can be blocked waiting for the `ptr` to change.
/// If the timeout delay is reached, the function returns `error.TimedOut`.
///
/// The comparison of the `ptr` value to `expected` is done atomically and totally-ordered
/// with respect to other atomic operations operating on the `ptr` memory location.
pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
    if (std.builtin.single_threaded and timeout == null) {
        if (@atomicLoad(u32, ptr, .SeqCst) != expected) return;
        @panic("deadlock detected");
    }

    if (timeout == @as(?u64, 0)) {
        if (@atomicLoad(u32, ptr, .SeqCst) != expected) return;
        return error.TimedOut;
    }

    return default.wait(ptr, expected, timeout);
}

/// Unblocks a set of threads waiting on the `ptr` to be changed by a matching `wait()`.
/// `waiters` is used as a hint for how many waiting threads to wake up.
/// Note that blocked threads can still wake up spuriously by timeout or other internal events.
pub fn wake(ptr: *const u32, waiters: u32) void {
    if (std.builtin.single_threaded or waiters == 0) {
        return;
    }

    return default.wake(ptr, waiters);
}

/// Futex implementation which blocks and unblocks kernel threads.
pub const thread = @import("futex/thread.zig");

/// Generic futex implementation in userspace using hashed wait queues.
pub const Generic = @import("futex/generic.zig").Generic;

/// The default futex implementation
pub const default = if (@hasDecl(root, "sync") and @hasDecl(root.sync, "futex"))
    root.sync.futex
else if (std.io.is_async)
    thread // TODO(kprotty): replace with std.event aware futex
else
    thread;

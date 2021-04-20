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
const target = std.Target.current;
const Instant = @import("./Instant.zig");

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

    return OsFutex.wait(ptr, expected, timeout);
}

/// Unblocks a set of threads waiting on the `ptr` to be changed by a matching `wait()`.
/// `waiters` is used as a hint for how many waiting threads to wake up.
/// Note that blocked threads can still wake up spuriously by timeout or other internal events.
pub fn wake(ptr: *const u32, waiters: u32) void {
    if (std.builtin.single_threaded or waiters == 0) {
        return;
    }

    return OsFutex.wake(ptr, waiters);
}

const OsFutex = if (target.isWindows())
    WindowsFutex
else if (target.isLinux())
    LinuxFutex
else if (target.isDarwin())
    DarwinFutex
else if (std.builtink.link_libc)
    PosixFutex
else
    @compileError("Futex implementation unsupported");

const WindowsFutex = struct {
    const windows = std.os.windows;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        // RtlWaitOnAddress uses a LARGE_INTEGER for timeouts.
        // The value is in units of 100 nanoseconds, with a negative value being a relative timeout.
        var timeout_val: windows.LARGE_INTEGER = undefined;
        var timeout_ptr: ?*const @TypeOf(timeout_val) = null;
        if (timeout) |timeout_ns| {
            timeout_ptr = &timeout_val;
            timeout_val = -@intCast(@TypeOf(timeout_val), timeout_ns / 100);
        }

        const status = RtlWaitOnAddress(
            @ptrCast(?*const c_void, ptr),
            @ptrCast(?*const c_void, &expected),
            @sizeOf(@TypeOf(expected)),
            timeout_ptr,
        );

        if (status == .TIMEOUT) {
            return error.TimedOut;
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        const address = @ptrCast(?*const c_void, ptr);
        switch (waiters) {
            1 => RtlWakeAddressSingle(address),
            else => RtlWakeAddressAll(address),
        }
    }
};

const LinuxFutex = struct {
    const linux = std.os.linux;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        var ts: std.os.timespec = undefined;
        var ts_ptr: ?*std.os.timespec = null;
        if (timeout) |timeout_ns| {
            ts_ptr = &ts;
            ts.tv_sec = @intCast(@TypeOf(ts.tv_sec), timeout_ns / std.time.ns_per_s);
            ts.tv_nsec = @intCast(@TypeOf(ts.tv_nsec), timeout_ns % std.time.ns_per_s);
        }

        switch (linux.getErrno(linux.futex_wait(
            @ptrCast(*const i32, ptr),
            linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAIT,
            @bitCast(i32, expected),
            ts_ptr,
        ))) {
            0 => {}, // notified by `wake()`
            std.os.EINTR => {}, // spurious wakeup
            std.os.EAGAIN => {}, // ptr.* != expected
            std.os.ETIMEDOUT => return error.TimedOut,
            std.os.EINVAL => {}, // possibly invalid timeout
            std.os.EFAULT => unreachable,
            else => unreachable,
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        switch (linux.getErrno(linux.futex_wake(
            @ptrCast(*const i32, ptr),
            linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAKE,
            std.math.cast(i32, waiters) catch std.math.maxInt(i32),
        ))) {
            0 => {}, // successful wake up
            std.os.EINVAL => {}, // invalid futex_wait() on ptr done elsewhere
            std.os.EFAULT => {}, // pointer became invalid while doing the wake
            else => unreachable,
        }
    }
};

const DarwinFutex = struct {
    const darwin = std.os.darwin;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        /// __ulock_wait() uses 0 timeout for infinite wait
        var timeout_us: u32 = 0;
        if (timeout) |timeout_ns| {
            timeout_us = std.math.cast(u32, timeout_ns / std.time.ns_per_us) catch std.math.maxInt(u32);
        }

        const status = darwin.__ulock_wait(
            darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO,
            @ptrCast(*const c_void, ptr),
            @as(u64, expected),
            timeout_us,
        );

        if (status >= 0) return;
        switch (-status) {
            darwin.EINTR => {},
            darwin.EFAULT => unreachable,
            darwin.ETIMEDOUT => return error.TimedOut,
            else => |errno| {
                const _discarded = std.os.unexpectedErrno(@intCast(usize, errno));
                unreachable;
            },
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        var flags: u32 = darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO;
        if (waiters > 1) {
            flags |= darwin.ULF_WAKE_ALL;
        }

        while (true) {
            // Darwin XNU 7195.50.7.100.1 introduced __ulock_wait2 and migrated code paths (notably pthread_cond_t) towards it:
            // https://github.com/apple/darwin-xnu/commit/d4061fb0260b3ed486147341b72468f836ed6c8f#diff-08f993cc40af475663274687b7c326cc6c3031e0db3ac8de7b24624610616be6
            //
            // This XNU version appears to correspond to 11.0.1:
            // https://kernelshaman.blogspot.com/2021/01/building-xnu-for-macos-big-sur-1101.html
            const addr = @ptrCast(*const c_void, ptr);
            const status = blk: {
                if (target.os.version_range.semver.max >= 11) {
                    break :blk darwin.__ulock_wait2(flags, addr, 0, 0);
                } else {
                    break :blk darwin.__ulock_wait(flags, addr, 0);
                }
            };

            if (status >= 0) return;
            switch (-status) {
                darwin.EINTR => continue, // spurious wake()
                darwin.ENOENT => return, // nothing was woken up
                darwin.EALREADY => unreachable, // only for ULF_WAKE_THREAD
                else => |errno| {
                    const _discarded = std.os.unexpectedErrno(@intCast(usize, errno));
                    unreachable;
                },
            }
        }
    }
};

const PosixFutex = struct {
    //! For posix systems, pthread doesn't provide a futex equivalent so we have to create one in userspace.
    //! The implementation here is sub-optimal and kept simple as of now to aid in review.
    //!
    //! TODO(kprotty):
    //! - Have a Waiter counter per Bucket which can be checked for > 0 before acquiring the Bucket mutex
    //! - Implement Rust's parking_lot's WordLock for the Bucket mutex instead of trusting pthread_mutex_t to handle micro-contention. 
    //! - Try switching from a flat list of Waiters per Bucket to a list of TailQueues for each address per Bucket
    //! - Convert said list of TailQueues into a self-balancing Tree of TailQueues for each address

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        const bucket = Bucket.from(ptr);
        bucket.lock();

        if (@atomicLoad(u32, ptr, .SeqCst) != expected) {
            bucket.unlock();
            return;
        }

        var waiter = Waiter{ .data = .{ .ptr = ptr } };
        bucket.queue.append(&waiter);
        bucket.unlock();

        var timed_out = false;
        waiter.data.event.wait(timeout) {
            timed_out = true;
        };

        if (timed_out) {
            bucket.lock();
            if (waiter.data.enqueued) {
                bucket.queue.remove(&waiter);
                bucket.unlock();
            } else {
                // A wake() thread already dequeued our Waiter 
                // and is in the process of setting its Event.
                bucket.unlock();
                timed_out = false;
                waiter.data.event.wait(null) catch unreachable;
            }
        }

        waiter.data.event.deinit();
        if (timed_out) {
            return error.TimedOut;
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        var notified = WaitQueue{};
        const bucket = Bucket.from(ptr);
        bucket.lock();

        var idle_waiter = bucket.queue.first;
        while (idle_waiter) |waiter| {
            idle_waiter = waiter.next;
            if (waiter.data.ptr != ptr) {
                continue;
            }

            waiter.data.enqueued = false;
            bucket.queue.remove(waiter);
            notified.append(waiter);

            std.debug.assert(waiters > 0);
            if (notified.len >= waiters) {
                break;
            }
        }

        bucket.unlock();
        while (notified.popFirst()) |waiter| {
            waiter.data.event.set();
        }
    }

    const Waiter = WaitQueue.Node;
    const WaitQueue = std.TailQueue(struct {
        ptr: *const u32,
        event: Event = .{},
        enqueued: bool = true,
    });

    const Bucket = struct {
        queue: WaitQueue = .{},
        mutex: std.c.pthread_mutex_t = .{},

        var table = [_]Bucket{.{}} ** 256;

        fn from(ptr: *const u32) callconv(.Inline) *Bucket {
            return &table[@ptrToInt(ptr) % table.len];
        }

        fn lock(self: *Bucket) callconv(.Inline) void {
            std.debug.assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
        }

        fn unlock(self: *Bucket) callconv(.Inline) void {
            std.debug.assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);
        }
    };

    const Event = struct {
        is_set: bool = false,
        cond: std.c.pthread_cond_t = .{},
        mutex: std.c.pthread_mutex_t = .{},

        fn deinit(self: *Event) void {
            // On certain systems like Dragonfly BSD,
            // the destroy functions can return EINVAL
            // if the pthread type is statically initialized.

            const rc = std.c.pthread_cond_destroy(&self.cond);
            std.debug.assert(rc == 0 or rc == std.os.EINVAL);

            const rm = std.c.pthread_mutex_destroy(&self.mutex);
            std.debug.assert(rm == 0 or rm == std.os.EINVAL);
        }

        fn set(self: *Event) void {
            std.debug.assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
            defer std.debug.assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);

            // Signal the condition variable while holding the mutex.
            // Without it, the waiter could wake up and deallocate the Event
            // after pthread_mutex_unlock() but before pthread_cond_signal().

            self.is_set = true;
            std.debug.assert(std.c.pthread_cond_signal(&self.cond) == 0);
        }

        fn wait(self: *Event, timeout: ?u64) error{TimedOut}!void {
            // Begin the starting point for the timeout outside the mutex.
            var started: Instant = undefined;
            if (timeout != null) {
                started = Instant.now();
            }

            std.debug.assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
            defer std.debug.assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);

            while (!self.is_set) {
                const timeout_ns = timeout orelse {
                    std.debug.assert(std.c.pthread_cond_wait(&self.cond, &self.mutex) == 0);
                    continue;
                };

                // Check for timeout using Instant as opposed to the result of pthread_cond_timedwait() below.
                // The latter uses the system time which is more prone to tampering or adjustments.
                // The former is *effectively* monotonic and should be more consistent. 
                const elapsed_ns = Instant.now().since(started) orelse 0;
                if (elapsed_ns >= timeout_ns) {
                    return error.TimedOut;
                }

                // pthread_cond_timedwait() operates with absolute timeouts based on the system clock.
                // Get the system clock timestamp using the most appropriate method.
                const delay_ns = timeout_ns - elapsed_ns;
                const timestamp_ns = blk: {
                    if (target.isDarwin()) {
                        var tv: std.os.timeval = undefined;
                        std.os.gettimeofday(&tv);
                        break :blk (@intCast(u64, tv.tv_sec) * std.time.ns_per_s) + (@intCast(u64, tv.tv_usec) * std.time.ns_per_us);
                    } else {
                        var ts: std.os.timespec = undefined;
                        std.os.clock_gettime(std.os.CLOCK_REALTIME, &ts) catch break :blk std.math.maxInt(u64);
                        break :blk (@intCast(u64, ts.tv_sec) * std.time.ns_per_s) + @intCast(u64, ts.tv_nsec);
                    }
                };

                var deadline_ns: u64 = undefined;
                if (@addWithOverflow(u64, timestamp_ns, delay_ns, &deadline_ns)) {
                    deadline_ns = std.math.maxInt(u64);
                }

                var ts: std.os.timespec = undefined;
                ts.tv_sec = std.math.cast(@TypeOf(ts.tv_sec), deadline_ns / std.time.ns_per_s) catch std.math.maxInt(@TypeOf(ts.tv_sec));
                ts.tv_nsec = @intCast(@TypeOf(ts.tv_nsec), deadline_ns % std.time.ns_per_s);

                switch (std.c.pthread_cond_timedwait(&self.cond, &self.mutex, &ts)) {
                    0 => {},
                    std.os.ETIMEDOUT => {}, // a timeout occured
                    std.os.EINVAL => {}, // an invalid (out of range?) timespec was provided - it will just busy-loop 
                    std.os.EPERM => unreachable,
                    else => unreachable,
                }
            }
        }
    };
};

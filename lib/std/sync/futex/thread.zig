// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const target = std.Target.current;
const assert = std.debug.assert;
const Instant = std.time.Instant;
const GenericFutex = @import("./generic.zig").Generic;

pub usingnamespace if (target.os.tag == .windows)
    WindowsFutex
else if (target.os.tag == .linux)
    LinuxFutex
else if (target.isDarwin())
    DarwinFutex
else if (std.builtink.link_libc)
    PosixFutex
else
    @compileError("Thread futex implementation not supported");

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

const PosixFutex = GenericFutex(struct {
    pub const Lock = PosixLock;
    pub const Event = PosixEvent;
    pub const shards = std.meta.bitCount(usize);

    const PosixLock = struct {
        mutex: std.c.pthread_mutex_t = .{},

        pub fn acquire(self: *PosixLock) void {
            assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
        }

        pub fn release(self: *PosixLock) void {
            assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);
        }
    };

    const PosixEvent = struct {
        cond: std.c.pthread_cond_t = .{},
        mutex: std.c.pthread_mutex_t = .{},
        state: enum{empty, waiting, notified} = .empty,

        pub fn deinit(self: *PosixEvent) void {
            // On certain systems like Dragonfly BSD,
            // the destroy functions can return EINVAL
            // if the pthread type is statically initialized.

            const rc = std.c.pthread_cond_destroy(&self.cond);
            assert(rc == 0 or rc == std.os.EINVAL);

            const rm = std.c.pthread_mutex_destroy(&self.mutex);
            assert(rm == 0 or rm == std.os.EINVAL);
        }

        /// Assuming ownership of the Event, reset its state in a cheap manner.
        /// Used only by PosixLock for trying to re-acquire the lock.
        fn reset(self: *PosixEvent) void {
            self.state = .empty;
        }

        pub fn set(self: *PosixEvent) void {
            assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
            defer assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);

            // Signal the condition variable while holding the mutex.
            // Without it, the waiter could wake up and deallocate the Event
            // after pthread_mutex_unlock() but before pthread_cond_signal().

            const state = self.state;
            assert(state != .notified);

            self.state = .notified;
            if (state == .waiting) {
                assert(std.c.pthread_cond_signal(&self.cond) == 0);
            }
        }

        pub fn wait(self: *PosixEvent, timeout: ?u64) error{TimedOut}!void {
            // Begin the starting point for the timeout outside the mutex.
            var started: Instant = undefined;
            if (timeout != null) {
                started = Instant.now();
            }

            assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
            defer assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);

            while (!self.is_set) {
                const timeout_ns = timeout orelse {
                    assert(std.c.pthread_cond_wait(&self.cond, &self.mutex) == 0);
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
});
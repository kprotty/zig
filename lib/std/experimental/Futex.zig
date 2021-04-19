// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const target = std.Target.current;
const Instant = @import("./Instant.zig");

pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
    if (timeout != @as(?u64, 0)) return OsFutex.wait(ptr, expected, timeout);
    return switch (@atomicLoad(u32, ptr, .SeqCst) == expected) {
        true => error.TimedOut,
        else => {},
    };
}

pub fn wake(ptr: *const u32, waiters: u32) void {
    if (waiters == 0) return;
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
            0 => {},
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
            0 => {},
            std.os.EINTR => {},
            std.os.EAGAIN => {},
            std.os.ETIMEDOUT => return error.TimedOut,
            else => unreachable,
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        switch (linux.getErrno(linux.futex_wake(
            @ptrCast(*const i32, ptr),
            linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAKE,
            std.math.cast(i32, waiters) catch std.math.maxInt(i32),
        ))) {
            0 => {},
            std.os.EINVAL => {},
            std.os.EACCES => {},
            std.os.EFAULT => {},
            else => unreachable,
        }
    }
};

const DarwinFutex = struct {
    const darwin = std.os.darwin;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
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
            darwin.EINTR => continue,
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
            const status = darwin.__ulock_wake(
                flags,
                @ptrCast(*const c_void, ptr),
                @as(u64, 0),
            );

            if (status >= 0) return;
            switch (-status) {
                darwin.ENOENT => {},
                darwin.EINTR => continue,
                else => |errno| {
                    const _discarded = std.os.unexpectedErrno(@intCast(usize, errno));
                    unreachable;
                },
            }
        }
    }
};

const PosixFutex = struct {
    const Bucket = struct {
        waiters: u32 = 0,
        cond: std.c.pthread_cond_t = std.c.PTHREAD_COND_INITIALIZER,
        mutex: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,

        var buckets = [_]Bucket{.{}} ** 256;

        fn from(ptr: *const u32) *Bucket {
            const address = @ptrToInt(ptr) >> @popCount(u3, @alignOf(u32) - 1);
            const seed = 0x9E3779B97F4A7C15 >> (64 - std.meta.bitCount(usize));
            const index = (address *% seed) % buckets.len;
            return &buckets[index];
        }
    };

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        var started: Instant = undefined;
        if (timeout != null) {
            started = Instant.now();
        }

        const bucket = Bucket.from(ptr);
        std.debug.assert(std.c.pthread_mutex_lock(&bucket.mutex) == 0);
        defer std.debug.assert(std.c.pthread_mutex_unlock(&bucket.mutex) == 0);

        @atomicStore(u32, &bucket.waiters, bucket.waiters + 1, .SeqCst);
        defer @atomicStore(u32, &bucket.waiters, bucket.waiters - 1, .SeqCst);

        while (@atomicLoad(u32, ptr, .SeqCst) == expected) {
            const timeout_ns = timeout orelse {
                std.debug.assert(std.c.pthread_cond_wait(&bucket.cond, &bucket.mutex) == 0);
                continue;
            };

            const elapsed = Instant.now().since(started) orelse 0;
            if (elapsed >= timeout_ns) {
                return error.TimedOut;
            }

            const delay = timeout_ns - elapsed;
            const timestamp = blk: {
                if (target.isDarwin()) {
                    var tv: std.os.timeval = undefined;
                    std.os.gettimeofday(&tv, null);
                    const secs = @intCast(u64, tv.tv_sec) * std.time.ns_per_s;
                    const nsecs = @intCast(u64, tv.tv_usec) * std.time.ns_per_us;
                    break :blk (secs + nsecs);
                }

                var ts: std.os.timespec = undefined;
                std.os.clock_gettime(std.os.CLOCK_REALTIME, &ts) catch {
                    ts.tv_sec = std.math.maxInt(@TypeOf(ts.tv_sec)) / std.time.ns_per_s;
                    ts.tv_nsec = std.time.ns_per_s - 1;
                };

                const secs = @intCast(u64, ts.tv_sec) * std.time.ns_per_s;
                const nsecs = @intCast(u64, ts.tv_nsec);
                break :blk (secs + nsecs);
            };

            var expires: u64 = undefined;
            if (@addWithOverflow(u64, expires, delay, &expires)) {
                expires = std.math.maxInt(u64);
            }

            var ts: std.os.timespec = undefined;
            ts.tv_sec = @intCast(@TypeOf(ts.tv_sec), expires / std.time.ns_per_s);
            ts.tv_nsec = @intCast(@TypeOf(ts.tv_nsec), expires % std.time.ns_per_s);

            switch (std.c.pthread_cond_timedwait(&bucket.cond, &bucket.mutex, &ts)) {
                0 => {},
                std.os.ETIMEDOUT => {},
                else => unreachable,
            }
        }
    }

    pub fn wake(ptr: *const u32, waiters: u32) void {
        const bucket = Bucket.from(ptr);
        if (@atomicLoad(u32, &bucket.waiters, .SeqCst) == 0) {
            return;
        }

        {
            std.debug.assert(std.c.pthread_mutex_lock(&bucket.mutex) == 0);
            defer std.debug.assert(std.c.pthread_mutex_unlock(&bucket.mutex) == 0);

            if (@atomicLoad(u32, &bucket.waiters, .SeqCst) == 0) {
                return;
            }
        }

        switch (waiters) {
            0 => unreachable,
            1 => std.debug.assert(std.c.pthread_cond_signal(&bucket.cond) == 0),
            else => std.debug.assert(std.c.pthread_cond_broadcast(&bucket.cond) == 0),
        }
    }
};

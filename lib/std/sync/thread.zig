// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const target = std.Target.current;
const assert = std.debug.assert;

const Instant = std.time.Instant;
const Duration = std.time.Duration;
const CoreWaitQueue = @import("./core.zig").WaitQueue;

pub const WaitQueue = if (target.os.tag == .windows)
    WindowsWaitQueue
else if (target.os.tag == .linux)
    LinuxWaitQueue
else if (target.isDarwin())
    DarwinWaitQueue
else if (std.builtink.link_libc)
    PosixWaitQueue
else
    @compileError("OS WaitQueue implementation not supported");

const LinuxFutex = FutexWaitQueue(struct {
    const linux = std.os.linux;

    pub fn wait(ptr: *const u32, expected: u32, duration: ?Duration) error{TimedOut}!void {
        var ts: std.os.timespec = undefined;
        var ts_ptr: ?*std.os.timespec = null;

        if (duration) |timeout| {
            const timeout_ns = timeout.asNanos();
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
});

const WindowsWaitQueue = struct {
    const windows = std.os.windows;
    const windows_version = target.os.version_range.windows;

    pub usingnamespace if (windows_version.isAtLeast(.win8))
        FutexWaitQueue(WaitOnAddressFutex)
    else if (windows_version.isAtLeast(.vista))
        MutexCondWaitQueue(SRWMutexCond)
    else if (windows_version.isAtLeast(.xp))
        NtKeyedEventWaitQueue
    else
        @compileError("Windows version is not supported");

    const WaitOnAddressFutex = struct {
        pub fn wait(ptr: *const u32, expected: u32, duration: ?Duration) error{TimedOut}!void {
            // RtlWaitOnAddress uses a LARGE_INTEGER for timeouts.
            // The value is in units of 100 nanoseconds, with a negative value being a relative timeout.
            var timeout_val: windows.LARGE_INTEGER = undefined;
            var timeout_ptr: ?*const @TypeOf(timeout_val) = null;

            if (duration) |timeout| {
                const timeout_ns = timeout.asNanos();
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

    const SRWMutexCond = struct {
        lock: windows.SRWLOCK = windows.SRWLOCK_INIT,
        cond: windows.CONDITION_VARIABLE = windows.CONDITION_VARIABLE_INIT,

        pub fn acquire(self: *SRWMutexCond) void {
            windows.kernel32.AcquireSRWLockExclusive(&self.lock);
        }

        pub fn release(self: *SRWMutexCond) void {
            windows.kernel32.ReleaseSRWLockExclusive(&self.lock);
        }

        pub fn signal(self: *SRWMutexCond) void {
            windows.kernel32.WakeConditionVariable(&self.cond);
        }

        pub fn wait(self: *SRWMutexCond, duration: ?Duration) error{TimedOut}!void {
            var timeout_ms: windows.DWORD = windows.INFINITE;
            if (duration) |timeout| {
                timeout_ms = std.math.cast(windows.DWORD, timeout.asMillis()) catch timeout_ms;
            }

            const status = windows.kernel32.SleepConditionVariableSRW(
                &self.cond,
                &self.lock,
                timeout_ms,
                @as(windows.ULONG, 0),
            );

            if (status == windows.FALSE) {
                const err_code = windows.kernel32.GetLastError();
                assert(err_code == .TIMEOUT);
                return error.TimedOut;
            }
        }
    };

    const NtKeyedEventWaitQueue = CoreWaitQueue(struct {
        pub const LockImpl = NtKeyedLock;
        pub const EventImpl = NtKeyedEvent;
        pub const InstantImpl = Instant;
        pub const num_shards = @as(windows.PEB, undefined).WaitOnAddressHashTable.len;

        const NtKeyedLock = struct {
            
        };

        const NtKeyedEvent = struct {

        };
    });
};



const DarwinFutex = struct {
    const darwin = std.os.darwin;
    const darwin_version = target.os.version_range.semver;

    pub usingnamespace if (UlockFutex.is_supported)
        FutexWaitQueue(UlockFutex)
    else
        PosixWaitQueue;

    const UlockFutex = struct {
        const is_supported = 

        pub fn wait(ptr: *const u32, expected: u32, duration: ?Duration) error{TimedOut}!void {
            /// __ulock_wait() uses 0 timeout for infinite wait
            var timeout_us: u32 = 0;
            if (duration) |timeout| {
                timeout_us = std.math.cast(u32, timeout.asMicros()) catch std.math.maxInt(u32);
            }

            // Darwin XNU 7195.50.7.100.1 introduced __ulock_wait2 and migrated code paths (notably pthread_cond_t) towards it:
            // https://github.com/apple/darwin-xnu/commit/d4061fb0260b3ed486147341b72468f836ed6c8f#diff-08f993cc40af475663274687b7c326cc6c3031e0db3ac8de7b24624610616be6
            //
            // This XNU version appears to correspond to 11.0.1:
            // https://kernelshaman.blogspot.com/2021/01/building-xnu-for-macos-big-sur-1101.html
            const addr = @ptrCast(*const c_void, ptr);
            const flags = darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO;
            const status = blk: {
                if (darwin_version.max >= 11) {
                    break :blk darwin.__ulock_wait2(flags, addr, expected, timeout_us, 0);
                } else {
                    break :blk darwin.__ulock_wait(flags, addr, expected, timeout_us);
                }
            };

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
                const addr = @ptrCast(*const c_void, ptr);
                const status = darwin.__ulock_wake(flags, addr, 0);

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
};
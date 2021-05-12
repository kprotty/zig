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

    /// Effectively the same bucket array size used in linux futex internally
    /// https://code.woboq.org/linux/linux/kernel/futex.c.html#3884
    pub const bucket_count: usize = 256;

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
        RtlWaitOnAddressWaitQueue
    else if (windows_version.isAtLeast(.vista))
        Kernel32WaitQueue
    else if (windows_version.isAtLeast(.xp))
        NtKeyedEventWaitQueue
    else
        @compileError("Windows version is not supported");

    const RtlWaitOnAddressWaitQueue = FutexWaitQueue(struct {
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
    });

    const Kernel32WaitQueue = MutexCondWaitQueue(struct {
        pub const MutexImpl = struct {
            lock: windows.SRWLOCK = windows.SRWLOCK_INIT,

            pub fn deinit(self: *MutexImpl) void {
                self.* = undefined;
            }

            pub fn acquire(self: *MutexImpl) void {
                windows.kernel32.AcquireSRWLockExclusive(&self.lock);
            }

            pub fn release(self: *MutexImpl) void {
                windows.kernel32.ReleaseSRWLockExclusive(&self.lock);
            }
        };

        pub const CondImpl = struct {
            cond: windows.CONDITION_VARIABLE = windows.CONDITION_VARIABLE_INIT,

            pub fn deinit(self: *CondImpl) void {
                self.* = undefined;
            }

            pub fn signal(self: *CondImpl) void {
                windows.kernel32.WakeConditionVariable(&self.cond);
            }

            pub fn wait(self: *CondImpl, mutex: *MutexImpl, duration: ?Duration) void {
                var timeout_ms: windows.DWORD = windows.INFINITE;
                if (duration) |timeout| {
                    timeout_ms = std.math.cast(windows.DWORD, timeout.asMillis()) catch timeout_ms;
                }

                const status = windows.kernel32.SleepConditionVariableSRW(
                    &self.cond,
                    &mutex.lock,
                    timeout_ms,
                    @as(windows.ULONG, 0),
                );

                if (status == windows.FALSE) {
                    const err_code = windows.kernel32.GetLastError();
                    assert(err_code == .TIMEOUT);
                }
            }
        };
    });

    const NtKeyedEventWaitQueue = CoreWaitQueue(struct {
        pub const LockImpl = NtKeyedLock;
        pub const EventImpl = NtKeyedEvent;
        pub const InstantImpl = Instant;
        pub const bucket_count: usize = @as(windows.PEB, undefined).WaitOnAddressHashTable.len;

        const NtKeyedLock = @compileError("TODO");

        const NtKeyedEvent = @compileError("TODO");
    });
};

const DarwinFutex = struct {
    const darwin = std.os.darwin;
    const darwin_version = target.os.version_range.semver;
    const is_apple_silicon = target.os.tag == .macos and target.cpu.arch == .aarch64;

    pub usingnamespace if (is_apple_silicon)
        FutexWaitQueue(UlockFutex)
    else if (UnfairLockWaitQueue.WaitLock.is_supported)
        UnfairLockWaitQueue
    else
        PosixWaitQueue;

    const UnfairLockWaitQueue = CoreWaitQueue(struct {
        pub const LockImpl = UnfairLockImpl;
        pub const EventImpl = PosixWaitQueue.WaitEvent;
        pub const InstantImpl = PosixWaitQueue.WaitInstant;
        pub const bucket_count: usize = 32; // conservative towards bad macho linkers

        const UnfairLockImpl = struct {
            oul: darwin.os_unfair_lock = .{},
            
            pub const is_supported = UlockFutex.is_supported;

            pub fn acquire(self: *UnfairLockImpl) void {
                darwin.os_unfair_lock_lock(&self.oul);
            }

            pub fn release(self: *UnfairLockImpl) void {
                darwin.os_unfair_lock_unlock(&self.oul);
            }
        };
    });

    const UlockFutex = struct {
        pub const is_supported = @compileError("TODO");

        pub const bucket_count: usize = PosixWaitQueue.bucket_count;

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

const PosixWaitQueue = MutexCondWaitQueue(struct {
    /// Same value used in facebook's folly ParkingLot implementation for non-futex platforms
    /// https://github.com/facebook/folly/blob/bd600cd4e88f664f285489c76b6ad835d8367cd2/folly/synchronization/ParkingLot.cpp#L25
    pub const bucket_count: usize = if (is_mobile) 256 else 4096;
    
    const is_mobile = target.isAndroid() or (target.os.tag == .ios) or is_low_power_device;
    const is_low_power_device = @compileError("TODO");

    pub const MutexImpl = struct {
        mutex: std.c.pthread_mutex_t = .{},

        pub fn deinit(self: *MutexImpl) void {
            // On certain systems like Dragonfly BSD,
            // the destroy functions can return EINVAL
            // if the pthread type is statically initialized.
            const rm = std.c.pthread_mutex_destroy(&self.mutex);
            assert(rm == 0 or rm == std.os.EINVAL);
            self.* = undefined;
        }

        pub fn acquire(self: *MutexImpl) void {
            assert(std.c.pthread_mutex_lock(&self.mutex) == 0);
        }

        pub fn release(self: *MutexImpl) void {
            assert(std.c.pthread_mutex_unlock(&self.mutex) == 0);
        }
    };

    pub const CondImpl = struct {
        cond: std.c.pthread_cond_t = .{},

        pub fn deinit(self: *CondImpl) void {
            // On certain systems like Dragonfly BSD,
            // the destroy functions can return EINVAL
            // if the pthread type is statically initialized.
            const rc = std.c.pthread_cond_destroy(&self.cond);
            assert(rc == 0 or rc == std.os.EINVAL);
            self.* = undefined;
        }

        pub fn signal(self: *CondImpl) void {
            assert(std.c.pthread_cond_signal(&self.cond) == 0);
        }

        pub fn wait(self: *CondImpl, mutex: *MutexImpl, duration: ?Duration) void {
            const timeout = duration orelse {
                assert(std.c.pthread_cond_wait(&self.cond, &mutex.mutex) == 0);
                return;
            };

            // pthread_cond_timedwait() operates with absolute timeouts based on the system clock.
            // Get the system clock timestamp using the most appropriate method.
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
            if (@addWithOverflow(u64, timestamp_ns, timeout.asNanos(), &deadline_ns)) {
                deadline_ns = std.math.maxInt(u64);
            }

            var ts: std.os.timespec = undefined;
            ts.tv_sec = std.math.cast(@TypeOf(ts.tv_sec), deadline_ns / std.time.ns_per_s) catch std.math.maxInt(@TypeOf(ts.tv_sec));
            ts.tv_nsec = @intCast(@TypeOf(ts.tv_nsec), deadline_ns % std.time.ns_per_s);

            switch (std.c.pthread_cond_timedwait(&self.cond, &mutex.mutex, &ts)) {
                0 => {},
                std.os.ETIMEDOUT => {}, // a timeout occured
                std.os.EINVAL => {}, // an invalid (out of range?) timespec was provided - it will just busy-loop 
                std.os.EPERM => unreachable,
                else => unreachable,
            }
        }
    };
});

fn MutexCondWaitQueue(comptime MutexCondImpl: type) type {
    return CoreWaitQueue(struct {
        pub const LockImpl = MutexCondImpl.MutexImpl;
        pub const EventImpl = MutexCondEvent;
        pub const InstantImpl = Instant;
        pub const bucket_count = MutexCondImpl.bucket_count;

        const MutexCondEvent = @compileError("TODO");
    });
}

fn FutexWaitQueue(comptime FutexImpl: type) type {
    return CoreWaitQueue(struct {
        pub const LockImpl = FutexLock;
        pub const EventImpl = FutexEvent;
        pub const InstantImpl = Instant;
        pub const bucket_count = FutexImpl.bucket_count;

        const FutexLock = @compileError("TODO");

        const FutexEvent = @compileError("TODO");
    });
}
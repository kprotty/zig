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

const atomic = @import("./atomic.zig");
const generic = @import("./generic.zig");
const CoreWaitQueue = generic.core.WaitQueue;

pub usingnamespace generic.primitivesFor(OsWaitQueue);    
    
const OsWaitQueue = if (target.os.tag == .windows)
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
        pub const EventImpl = ThreadEvent(NtKeyedEvent);
        pub const InstantImpl = Instant;
        pub const bucket_count: usize = @as(windows.PEB, undefined).WaitOnAddressHashTable.len;

        const KeyedEvent = struct {
            var global_handle: ?windows.HANDLE = windows.INVALID_HANDLE_VALUE;

            fn getHandle() ?windows.HANDLE {
                const handle = atomic.load(&global_handle, .Relaxed) orelse return null;
                if (handle != windows.INVALID_HANDLE_VALUE) return handle;
                return getHandleSlow();
            }

            fn getHandleSlow() ?windows.HANDLE {
                @setCold(true);

                var handle: windows.HANDLE = undefined;
                const access_mask = windows.GENERIC_READ | windows.GENERIC_WRITE;
                const status = windows.ntdll.NtCreateKeyedEvent(&handle, access_mask, null, 0);
                
                // NULL keyed event handle is valid and represents the system wide keyed event handle
                const new_handle = return switch (status) {
                    .SUCCESS => handle,
                    else => null,
                };

                // Try to racily update the global handle with the new one we just made
                const current_handle = atomic.compareAndSwap(
                    &global_handle,
                    windows.INVALID_HANDLE_VALUE,
                    new_handle,
                    .Relaxed,
                    .Relaxed,
                ) orelse return new_handle;

                // If we failed the race, destroy the new handle we made
                windows.CloseHandle(new_handle);
                return current_handle;
            }

            fn wait(ptr: anytype, duration: ?Duration) void {
                var timeout_ptr: ?*windows.LARGE_INTEGER = null;
                var timeout_value: windows.LARGE_INTEGER = undefined;

                // NtWaitForKeyedEvent uses timeout unit where
                // - negative values indicate a relative timeout
                // - the value is in units of 100 nanoseconds
                if (duration) |timeout| {
                    timeout_ptr = &timeout_value;
                    timeout_value = -@intCast(windows.LARGE_INTEGER, timeout.asNanos() / 100);
                }
                
                const status = windows.ntdll.NtWaitForKeyedEvent(
                    KeyedEvent.getHandle(),
                    @ptrCast(*const c_void, ptr),
                    windows.FALSE, // non-alertable wait
                    timeout_ptr,
                );

                switch (status) {
                    .SUCCESS => {},
                    .TIMEOUT => {},
                    else => unreachable,
                }
            }

            fn notify(ptr: anytype) void {
                const status = windows.ntdll.NtReleaseKeyedEvent(
                    KeyedEvent.getHandle(),
                    @ptrCast(*const c_void, ptr),
                    windows.FALSE, // non-alertable wait
                    null,
                );
                assert(status == .SUCCESS);
            }
        }

        const NtKeyedLock = struct {
            state: usize = 0,

            const Self = @This();
            const LOCKED: usize = 1 << 0;
            const WAKING: usize = 1 << 1;
            const WAITING: usize = 1 << 2;

            pub fn deinit(self: *Self) void {
                self.* = undefined;
            }

            fn tryAcquire(self: *Self) callconv(.Inline) bool {
                return atomic.bitSet(
                    &self.state,
                    @ctz(usize, LOCKED),
                    .Acquire,
                ) == 0;
            }
            
            pub fn acquire(self: *Self) void {
                if (!self.tryAcquire()) {
                    self.acquireSlow();
                }
            }

            fn acquireSlow(self: *Self) void {
                @setCold(true);

                var adaptive_spin: usize = 0;
                var state = atomic.load(&self.state, .Relaxed);

                while (true) {
                    if (state & LOCKED == 0) {
                        if (self.tryAcquire()) {
                            return;
                        }

                        _ = windows.kernel32.SwitchToThread();
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    if ((state < WAITING) and (adaptive_spin < 4000)) {
                        atomic.spinLoopHint();
                        adaptive_spin += 1;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    var new_state: usize = undefined;
                    if (@addWithOverflow(usize, state, WAITING, &new_state)) {
                        unreachable; // Too many waiters on the same lock
                    }

                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        new_state,
                        .Relaxed,
                        .Relaxed,
                    )) |updated| {
                        state = updated;
                        continue;
                    }

                    KeyedEvent.wait(&self.state, null);

                    adaptive_spin = 0;
                    state = atomic.fetchSub(&self.state, WAITING | WAKING, .Relaxed);
                    state -= WAITING | WAKING;
                }
            }

            pub fn release(self: *Self) void {
                const state = atomic.fetchSub(&self.state, LOCKED, .Release);
                if ((state >= WAITING) and (state & WAKING == 0)) {
                    self.releaseSlow();
                }
            }

            fn releaseSlow(self: *Self) void {
                @setCold(true);

                var state = atomic.load(&self.state, .Relaxed);
                while (true) {
                    if ((state < WAITING) or (state & WAKING != 0)) {
                        return;
                    }

                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state | WAKING,
                        .Relaxed,
                        .Relaxed,
                    ) orelse {
                        KeyedEvent.notify(&self.state);
                        return;
                    };
                }
            }
        };

        const NtKeyedEvent = struct {
            state: State = .empty,

            const Self = @This();
            const State = enum(usize) {
                empty,
                waiting,
                notified,
            };

            pub fn init(self: *Self) void {
                self.* = .{};
            }

            pub fn deinit(self: *Self) void {
                assert(self.state != .waiting);
                self.* = undefined;
            }

            pub fn wait(self: *Self, deadline: ?Instant) error{TimedOut}!void {
                if (atomic.compareAndSwap(
                    &self.state,
                    .empty,
                    .waiting,
                    .Acquire,
                    .Acquire,
                )) |state| {
                    assert(state == .notified);
                    return;
                }

                const instant = deadline orelse {
                    KeyedEvent.wait(&self.state, null);
                    assert(self.state == .notified);
                    return;
                };

                var timed_out = false;
                const duration = instant.since(Instant.now()) orelse blk: {
                    timed_out = true;
                    break :blk undefined;
                };

                if (!timed_out) {
                    KeyedEvent.wait(&self.state, duration);
                    timed_out = instant.since(Instant.now()) == null;
                }

                if (!timed_out) {
                    assert(self.state == .notified);
                    return;
                }

                const state = atomic.compareAndSwap(
                    &self.state,
                    .waiting,
                    .empty,
                    .Acquire,
                    .Acquire,
                ) orelse return error.TimedOut;
                assert(state == .notified);
                return;
            }

            pub fn set(self: *Self) void {
                switch (atomic.swap(&self.state, .notified, .Release)) {
                    .empty => {},
                    .waiting => KeyedEvent.notify(&self.state),
                    .notified => unreachable, // Event was notified more than once
                }
            }
        };
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
        pub const bucket_count = PosixWaitQueue.bucket_count;

        const UnfairLockImpl = struct {
            oul: darwin.os_unfair_lock = .{},
            
            pub const is_supported = UlockFutex.is_supported;

            pub fn deinit(self: *UnfairLockImpl) void {
                self.* = undefined;
            }

            pub fn acquire(self: *UnfairLockImpl) void {
                darwin.os_unfair_lock_lock(&self.oul);
            }

            pub fn release(self: *UnfairLockImpl) void {
                darwin.os_unfair_lock_unlock(&self.oul);
            }
        };
    });

    const UlockFutex = struct {
        pub const is_supported = switch (target.os.tag) {
            .macos => darwin_version.isAtLeast(.{ .major = 10, .minor = 12 }),
            .ios => darwin_version.isAtLeast(.{ .major = 10, .minor = 0 }),
            .tvos => darwin_version.isAtLeast(.{ .major = 10, .minor = 0 }),
            .watchos => darwin_version.isAtLeast(.{ .major = 3, .minor = 0 }),
            else => false,
        };

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
    
    const is_mobile = target.isAndroid() or is_ios or is_low_power_device;
    const is_ios = target.os.tag == .ios;
    const is_low_power_device = arch.isARM() or arch.isThumb() or arch.isWasm() or arch.isMIPS();
    const arch = target.cpu.arch;

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

/// Implements a CoreWaitQueue backed by a Mutex and Condvar implementation
fn MutexCondWaitQueue(comptime MutexCondImpl: type) type {
    return CoreWaitQueue(struct {
        pub const LockImpl = MutexCondImpl.MutexImpl;
        pub const EventImpl = ThreadEvent(MutexCondEvent);
        pub const InstantImpl = Instant;
        pub const bucket_count = MutexCondImpl.bucket_count;

        const MutexCondEvent = struct {
            state: State = .empty,
            mutex: MutexCondImpl.MutexImpl,
            cond: MutexCondImpl.CondImpl,

            const State = enum{
                empty,
                waiting,
                notified,
            };

            pub fn init(self: *MutexCondEvent) void {
                self.* = .{};
            }

            pub fn deinit(self: *MutexCondEvent) void {
                assert(self.state != .waiting);
                self.mutex.deinit();
                self.cond.deinit();
                self.* = undefined;
            }

            pub fn wait(self: *MutexCondEvent, deadline: ?Instant) error{TimedOut}!void {
                self.mutex.acquire();
                defer self.mutex.release();

                switch (self.state) {
                    .empty => self.state = .waiting,
                    .waiting => unreachable, // multiple threads waiting on same Event
                    .notified => return,
                }

                while (true) {
                    assert(self.state == .waiting);

                    var timeout: ?Duration = null;
                    if (deadline) |instant| {
                        timeout = instant.since(Instant.now()) orelse {
                            self.state = .empty;
                            return error.TimedOut;
                        };
                    }

                    self.cond.wait(&self.mutex, timeout);
                    switch (self.state) {
                        .empty => unreachable, // Event was unset while a thread was waiting
                        .waiting => {},
                        .notified => return,
                    }
                }
            }

            pub fn set(self: *MutexCondEvent) void {
                self.mutex.acquire();
                defer self.mutex.release();

                switch (self.state) {
                    .empty => self.state = .notified,
                    .waiting => {
                        // Signal the condition variable with the mutex held since,
                        // when the mutex is unlocked, the Event waiter could wake up,
                        // see self.state == .notified, stop waiting and deallocate the Event object.
                        self.state = .notified;
                        self.cond.signal();
                    },
                    .notified => unreachable, // Event was set more than once
                }
            }
        };
    });
}

/// Implements a CoreWaitQueue backed by a Futex implementaiton
fn FutexWaitQueue(comptime FutexImpl: type) type {
    return CoreWaitQueue(struct {
        pub const LockImpl = FutexLock;
        pub const EventImpl = ThreadEvent(FutexEvent);
        pub const InstantImpl = Instant;
        pub const bucket_count = FutexImpl.bucket_count;

        const FutexLock = struct {
            state: State = .unlocked,

            const State = enum(u32) {
                unlocked,
                locked,
                contended,
            };

            pub fn deinit(self: *FutexLock) void {
                self.* = undefined;
            }

            pub fn acquire(self: *FutexLock) void {
                if (atomic.tryCompareAndSwap(
                    &self.state,
                    .unlocked,
                    .locked,
                    .Acquire,
                    .Relaxed,
                )) |_| {
                    self.acquireSlow();
                }
            }

            fn acquireSlow(self: *FutexLock) void {
                @setCold(true);

                var adaptive_spin: u8 = 0;
                var new_state = State.locked;
                var state = atomic.load(&self.state, .Relaxed);
                
                while (true) {
                    if (state == .unlocked) {
                        state = atomic.tryCompareAndSwap(
                            &self.state,
                            state,
                            new_state,
                            .Acquire,
                            .Relaxed,
                        ) orelse return;
                        continue;
                    }

                    if (state != .contended) {
                        if (adaptive_spin < 5) {
                            var spin = @as(usize, 1) << @intCast(std.math.Log2Int(usize), adaptive_spin);
                            while (spin > 0) : (spin -= 1) {
                                atomic.spinLoopHint();
                            }

                            adaptive_spin += 1;
                            state = atomic.load(&self.state, .Relaxed);
                            continue;
                        }

                        if (atomic.tryCompareAndSwap(
                            &self.state,
                            state,
                            new_state,
                            .Acquire,
                            .Relaxed,
                        )) |updated| {
                            state = updated;
                            continue;
                        }
                    }

                    _ = FutexImpl.wait(
                        @ptrCast(*const u32, &self.state),
                        @enumToInt(State.contended),
                        null,
                    ) catch unreachable;

                    adaptive_spin = 0;
                    new_state = .contended;
                    state = atomic.load(&self.state, .Relaxed);
                }
            }

            pub fn release(self: *FutexLock) void {
                switch (atomic.swap(&self.state, .unlocked, .Release)) {
                    .unlocked => unreachable, // unlocked an unlocked Mutex
                    .locked => {}, // unlocked a locked Mutex (the expected)
                    .contended => { // unlocked a Mutex with (possibly) pending waiters
                        const ptr = @ptrCast(*const u32, &self.state);
                        FutexImpl.wake(ptr, 1);
                    },
                }
            }
        };

        const FutexEvent = struct {
            state: State = .empty,

            const State = enum(u32){
                empty,
                waiting,
                notified,
            };

            pub fn init(self: *MutexCondEvent) void {
                self.* = .{};
            }

            pub fn deinit(self: *MutexCondEvent) void {
                assert(self.state != .waiting);
                self.* = undefined;
            }

            pub fn wait(self: *MutexCondEvent, deadline: ?Instant) error{TimedOut}!void {
                if (atomic.compareAndSwap(&self.state, .empty, .waiting, .Acquire, .Acquire)) |state| {
                    assert(state == .notified);
                    return;
                }

                while (true) {
                    var timeout: ?Duration = null;
                    if (deadline) |instant| {
                        timeout = instant.since(Instant.now()) orelse {
                            const state = atomic.compareAndSwap(
                                &self.state,
                                .waiting,
                                .empty,
                                .Acquire,
                                .Acquire,
                            ) orelse return error.TimedOut;
                            assert(state == .notified);
                            return;
                        };
                    }

                    _ = FutexImpl.wait(
                        @ptrCast(*const u32, &self.state),
                        @enumToInt(State.waiting),
                        timeout,
                    ) catch {
                        assert(timeout != null);
                    };

                    switch (atomic.load(&self.state, .Relaxed)) {
                        .empty => unreachable, // Event is unset while there's a waiter
                        .waiting => {},
                        .notified => return,
                    }
                }
            }

            pub fn set(self: *MutexCondEvent) void {
                switch (atomic.swap(&self.state, .notified, .Release)) {
                    .empty => {},
                    .waiting => {
                        const ptr = @ptrCast(*const u32, &self.state);
                        FutexImpl.wake(ptr, 1);
                    },
                    .notified => unreachable, // Event was set multiple times
                }
            }
        };
    });
}

fn ThreadEvent(comptime EventImpl: type) type {
    return struct {
        impl: EventImpl,

        const Self = @This();

        pub fn init(self: *Self) void {
            return self.impl.init();
        }

        pub fn deinit(self: *Self) void {
            return self.impl.deinit();
        }

        pub fn wait(self: *Self, deadline: ?Instant) error{TimedOut}!void {
            if (std.builtin.single_threaded and deadline == null) {
                @panic("deadlock detected");
            } else {
                return self.impl.wait(deadline);
            }
        }

        pub fn set(self: *Self) void {
            if (std.builtin.single_threaded) {
                unreachable;
            } else {
                return self.impl.set();
            }
        }
    };
}
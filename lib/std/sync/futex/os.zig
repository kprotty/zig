// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");
const generic = @import("./generic.zig");
const SpinFutex = @import("./spin.zig");

const builtin = std.builtin;
const assert = std.debug.assert;

pub usingnamespace if (builtin.os.tag == .windows)
    WindowsFutex
else if (builtin.os.tag == .linux)
    LinuxFutex
else if (std.Target.current.isDarwin())
    DarwinFutex
else if (builtin.link_libc)
    PosixFutex
else
    SpinFutex;

const LinuxFutex = struct {
    const linux = std.os.linux;

    pub const Lock = generic.GenericFutexLock(@This());

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        var ts: linux.timespec = undefined;
        var ts_ptr: ?*const linux.timespec = null;

        if (timeout) |timeout_ns| {
            const secs = @divFloor(timeout_ns, std.time.ns_per_s);
            const nsecs = @mod(timeout_ns, std.time.ns_per_s);
            ts_ptr = &ts;
            ts.tv_sec = std.math.cast(@TypeOf(ts.tv_sec), secs) catch std.math.maxInt(@TypeOf(ts.tv_sec));
            ts.tv_nsec = std.math.cast(@TypeOf(ts.tv_nsec), nsecs) catch std.math.maxInt(@TypeOf(ts.tv_nsec));
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
            else => |errno| {
                const err = std.os.unexpectedErrno(errno);
                unreachable;
            },
        }
    }

    pub fn wake(ptr: *const u32) void {
        switch (linux.getErrno(linux.futex_wake(
            @ptrCast(*const i32, ptr),
            linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAKE,
            1, // max waiters to wake
        ))) {
            0 => {},
            std.os.EACCES => {},
            std.os.EFAULT => {},
            std.os.EINVAL => {},
            else => |errno| {
                const err = std.os.unexpectedErrno(errno);
                unreachable;
            },
        }
    }

    pub fn yield(iteration: usize) bool {
        if (iteration > 10) {
            return false;
        }

        // On linux we don't use sched_yield...
        // https://www.realworldtech.com/forum/?threadid=189711&curpostid=189752
        //
        // As per the maximum spin count, it;s the same as glibc:
        // But instead of static/single spins in glibc, we do spinning wih a backoff
        // https://elixir.bootlin.com/glibc/latest/source/sysdeps/generic/adaptive_spin_count.h
        var spins = blk: {
            const max_spins = 100;
            const shift = @intCast(std.math.Log2Int(usize), iteration);
            break :blk std.math.min(max_spins, @as(usize, 1) << shift);
        };

        while (spins > 0) : (spins -= 1) {
            atomic.spinLoopHint();
        }

        return true;
    }
};

const DarwinFutex = struct {
    const darwin = std.os.darwin;
    const Futex = if (UlockFutex.is_supported) UlockFutex else PosixFutex;

    pub const Lock = Futex.Lock;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        return Futex.wait(ptr, expected, timeout);
    }

    pub fn wake(ptr: *const u32) void {
        return Futex.wake(ptr);
    }

    pub fn yield(iteration: usize) bool {
        // Its not really benefitial to yield on darwin unless using the low-level Futex lock.
        return false;
    }

    const UlockFutex = struct {
        // See: https://github.com/apple/darwin-libplatform/search?q=OS_UNFAIR_LOCK_AVAILABILITY
        const version = std.Target.current.os.version_range.semver.min;
        const is_supported = switch (builtin.os.tag) {
            .macos => (version.major >= 10) and (version.minor >= 12),
            .ios => (version.major >= 10) and (version.minor >= 0),
            .tvos => (version.major >= 10) and (version.minor >= 0),
            .watchos => (version.major >= 3) and (version.minor >= 0),
            else => unreachable,
        };
        
        const Lock = struct {
            os_lock: darwin.os_unfair_lock = darwin.OS_UNFAIR_LOCK_INIT,

            pub fn acquire(self: *Lock) void {
                if (!darwin.os_unfair_lock_trylock(&self.os_lock)) {
                    self.acquireSlow();
                }
            }

            fn acquireSlow(self: *Lock) void {
                @setCold(true);

                // os_unfair_lock_lock() doesn't spin before calling __ulock_wait()
                // due to CPU spinning or yielding wasting battery and being ineffective 
                // on mobile platforms such as iOS and watchOS.
                //
                // Adaptive spinning appears to actually be performant for micro-contention
                // under certain environments so we implement it manually here in accordance 
                // to os_unfair_lock internals:
                // https://github.com/apple/darwin-libplatform/blob/main/src/os/lock.c
                //
                // These are the max spin counts before yielding for OSSpinLock:
                // https://github.com/apple/darwin-libplatform/search?q=OS_LOCK_SPIN_SPIN_TRIES
                const max_adaptive_spin = switch (builtin.os.tag) {
                    .macos => switch (builtin.arch) {
                        .arm, .aarch64 => 100,
                        else => 1000,
                    },
                    else => 0, // don't spin on non-desktop/laptop devices
                };

                var adaptive_spin: usize = 0;
                while (adaptive_spin < max_adaptive_spin) : (adaptive_spin += 1) {
                    // If there's threads waiting on the lock, then theres no need to spin.
                    // Mach port values are assumed to always have OS_ULOCK_NOWAITERS_BIT set.
                    // When unset, it indicates the existence of waiting threads for unlock.
                    const oul_value = atomic.load(&self.os_lock.oul_value, .Relaxed);
                    if (oul_value & darwin.OS_ULOCK_NOWAITERS_BIT == 0) {
                        break;
                    }

                    // Try to grab the lock when its unlocked.
                    if (oul_value == OS_LOCK_NO_OWNER) {
                        if (darwin.os_unfair_lock_trylock(&self.os_lock)) {
                            return;
                        }
                    }

                    // On the last runs of spinning, yield the OS thread instead of spinning.
                    // Since we're working with os_unfair_lock, we know which thread to yield to. 
                    if (adaptive_spin < max_adaptive_spin - 5) {
                        atomic.spinLoopHint();
                    } else {
                        _ = darwin.thread_switch(
                            darwin.OS_ULOCK_OWNER(oul_value),
                            darwin.SWITCH_OPTION_DEPRESS,
                            1, // timeout_ms
                        );
                    }
                }

                // Fallback to normal blocking lock.
                darwin.os_unfair_lock_lock(&self.os_lock);
            }

            pub fn release(self: *Self) void {
                darwin.os_unfair_lock_unlock(&self.os_lock);
            }
        };

        fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
            // timeout = 0 indicates TIMEOUT_WAIT_FOREVER
            // https://github.com/apple/darwin-xnu/blob/main/bsd/kern/sys_ulock.c
            var timeout_us: u32 = 0;
            if (timeout) |timeout_ns| {
                const timeout_unit = timeout_ns / std.time.ns_per_us;
                timeout_us = std.math.cast(u32, timeout_unit) catch std.math.maxInt(u32);
            }

            const rc = darwin.__ulock_wait(
                darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO,
                @ptrCast(*const c_void, ptr),
                @as(u64, expect),
                timeout_us,
            );

            if (ret < 0) {
                switch (-ret) {
                    darwin.EINTR => continue,
                    darwin.EFAULT => unreachable,
                    darwin.ETIMEDOUT => return error.TimedOut,
                    else => |errno| {
                        const err = std.os.unexpectedErrno(@intCast(usize, errno));
                        unreachable;
                    },
                }
            }
        }

        fn wake(ptr: *const u32) void {
            while (true) {
                const ret = darwin.__ulock_wake(
                    darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO,
                    @ptrCast(*const c_void, ptr),
                    @as(u64, 0),
                );

                if (ret < 0) {
                    switch (-ret) {
                        darwin.ENOENT => {},
                        darwin.EFAULT => {},
                        darwin.EINTR => continue,
                        else => |errno| {
                            const err = std.os.unexpectedErrno(@intCast(usize, errno));
                            unreachable;
                        },
                    }
                }

                return;
            }
        }
    };
};

const PosixFutex = struct {
    const c = std.c;
    const Futex = generic.GenericFutex(struct {
        pub const Event: type = PosixEvent;
        pub const Timestamp: type = PosixTimestamp;
        pub const bucket_count: usize = std.meta.bitCount(usize);
    });

    pub const Lock = Futex.Lock;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        return futex.wait(ptr, expected, timeout);
    }

    pub fn wake(ptr: *const u32) void {
        return futex.wake(ptr);
    }

    pub fn yield(iteration: usize) bool {
        // Appears to be a good spin limit for sched_yield() calls
        // https://trac.webkit.org/browser/webkit/trunk/Source/WTF/wtf/WordLock.cpp#L67
        if (iteration >= 40) {
            return false;
        }

        std.os.sched_yield() catch {};
        return true;
    }

    const PosixTimestamp = struct {};

    const PosixEvent = struct {};
};

const WindowsFutex = struct {
    const windows = std.os.windows;
    const futex = GenericFutex(struct {
        pub const Lock: type = NtEventLock;
        pub const Event: type = NtEvent;
        pub const Timestamp: type = NtTimestamp;
        pub const bucket_count: usize = 128;
    });

    /// Use our implemented Lock when available instead of the generic Futex one.
    pub const Lock = if (SRWLock.is_supported) SRWLock else NtLock;

    pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
        return futex.wait(ptr, expected, timeout);
    }

    pub fn wake(ptr: *const u32) void {
        return futex.wake(ptr);
    }

    pub fn yield(iteration: usize) bool {
        // Uses an adaptive spinning strategy where the spin count is based on kernel32's CRITICAL_SECTION.
        // https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionandspincount
        const max_iteration = 4000;
        if (iteration >= max_iteration) {
            return false;
        }

        // adaptive yielding:
        // - yield hardware thread (hyperthreading)
        // - yield OS thread to another running on same core
        // - yield OS thread to another running anywhere in system
        if (iteration < max_iteration - 20) {
            atomic.spinLoopHint();
        } else if (iteration < max_iteration - 10) {
            _ = windows.kernel32.SwitchToThread();
        } else {
            windows.kernel32.Sleep(0);
        }

        return true;
    }

    /// Slim-Reader/Writer Locks is a fast RWLock provided by kernel32 from Windows Vista and onwards.
    /// It has the opportunity to be priority inheritant in the future so we use this for our Futex.Lock impl
    /// instead of NtLock down below.
    ///
    /// https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializesrwlock
    const SRWLock = struct {
        srw_lock: windows.SRWLOCK = windows.SRWLOCK_INIT,

        const Self = @This();
        const is_supported = std.Target.current.os.version_range.windows.isAtLeast(.vista) orelse false;

        pub fn acquire(self: *Self) void {
            windows.kernel32.AcquireSRWLockExclusive(&self.srw_lock);
        }

        pub fn release(self: *Self) void {
            windows.kernel32.ReleaseSRWLockExclusive(&self.srw_lock);
        }
    };

    /// A ParkingLot Config-friendly wrapper for NtLock down below.
    const NtEventLock = struct {
        nt_lock: NtLock = .{},

        const Self = @This();
        pub const Held = void;

        pub fn acquire(self: *Self, held: *Held) void {
            return self.nt_lock.acquire();
        }

        pub fn release(self: *Self, held: *Held) void {
            return self.nt_lock.release();
        }
    };

    const NtTimestamp = struct {
        interrupt_time_100ns: u64,

        const Self = @This();

        pub fn now() Self {
            // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
            // https://golang.org/src/runtime/sys_windows_amd64.s
            const KUSER_SHARED_DATA = 0x7FFE0000;
            const INTERRUPT_TIME = KUSER_SHARED_DATA + 0x8;

            while (true) {
                // Must reaed user_high, then user_low, then kernel_high.
                // Snapshot is valid if user_high == kernel_high.
                // TODO: would volatile reads break ordering?
                const user_time_high = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 4), .SeqCst);
                const user_time_low = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 0), .SeqCst);
                const kernel_time_high = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 8), .SeqCst);

                if (user_time_high != kernel_time_high) {
                    atomic.spinLoopHint();
                    continue;
                }

                var interrupt_time = @as(u64, user_time_low);
                interrupt_time |= @as(u64, user_time_high) << 32;
                return Self{ .interrupt_time_100ns = interrupt_time };
            }
        }

        pub fn expires(self: Self, current_now: Self) bool {
            return current_now.interrupt_time_100ns > self.interrupt_time_100ns;
        }

        pub fn update(self: *Self, current_now: Self, rng: u64) void {
            // The interrupt time updates every 1ms to ~16ms
            // so when it does increment, probably enough time has passed (>=1ms) to expire it.
            self.interrupt_time_100ns += 1;
        }
    };

    const NtKeyedEvent = struct {
        /// Wait on a wake() notification for a key using NtKeyedEvents.
        pub fn wait(key: *const u32, timeout: ?u64) error{TimedOut}!void {
            var timeout_value: windows.LARGE_INTEGER = undefined;
            var timeout_ptr: ?*const windows.LARGE_INTEGER = null;

            if (timeout) |timeout_ns| {
                const timeout_units = @divFloor(timeout_ns, 100); // windows works with time units in 100ns
                const timeout_unit = std.math.cast(windows.LARGE_INTEGER, timeout_units) catch std.math.maxInt(windows.LARGE_INTEGER);
                timeout_value = -(timeout_unit); // A negative value represents relative timeout while positive is absolute.
                timeout_ptr = &timeout_value;
            }

            switch (windows.ntdll.NtWaitForKeyedEvent(
                getEventHandle(),
                @ptrCast(*const c_void, key),
                windows.FALSE, // non-alertable wait
                timeout_ptr,
            )) {
                .SUCCESS => {},
                .TIMEOUT => return error.TimedOut,
                else => |status| {
                    const err = windows.unexpectedStatus(status);
                    unreachable;
                },
            }
        }

        /// Wake up a wait()'ing thread on the key using NtKeyedEvents.
        /// Blocks until it finds a thread to wake up (unlike futexes).
        pub fn wake(key: *const u32) void {
            switch (windows.ntdll.NtReleaseKeyedEvent(
                getEventHandle(),
                @ptrCast(*const c_void, key),
                windows.FALSE, // non-alertable wait
                null,
            )) {
                .SUCCESS => {},
                else => |status| {
                    const err = windows.unexpectedStatus(status);
                    unreachable;
                },
            }
        }

        var event_handle: ?windows.HANDLE = windows.INVALID_HANDLE_VALUE;

        /// Get the process-wide keyed event handle (null is a valid value).
        fn getEventHandle() ?windows.HANDLE {
            const handle = atomic.load(&event_handle, .Relaxed);
            if (handle != windows.INVALID_HANDLE_VALUE) {
                return handle;
            } else {
                return getEventHandleSlow();
            }
        }

        fn getEventHandleSlow() ?windows.HANDLE {
            @setCold(true);

            // Try to create a keyed event handle for this process.
            var handle: windows.HANDLE = undefined;
            const status = windows.ntdll.NtCreateKeyedEvent(
                &handle,
                windows.GENERIC_READ | windows.GENERIC_WRITE,
                null,
                @as(windows.ULONG, 0),
            );

            // If we're unable to, fallback to the global keyed event handle (null).
            // We try to create our own in case the global handle is heavily contended by other processes.
            //
            // The global handle can also be obtained via NtOpenKeyedEvent(L"\KernelObjects\CritSecOutOfMemoryEvent").
            // http://joeduffyblog.com/2006/11/28/windows-keyed-events-critical-sections-and-new-vista-synchronization-features/
            var new_handle: ?windows.HANDLE = null;
            if (status == .SUCCESS) {
                new_handle = handle;
            }

            // Try to set our process event handle if it doesn't have one.
            const updated_handle = atomic.compareAndSwap(
                &event_handle,
                windows.INVALID_HANDLE_VALUE,
                new_handle,
                .Relaxed,
                .Relaxed,
            ) orelse return new_handle;

            // If our process already had an event handle (another thread won the race)
            // then we need to free our own if we created one to avoid a leak.
            if (status == .SUCCESS) {
                windows.CloseHandle(handle);
            }

            return updated_handle;
        }
    };

    const NtLock = struct {
        state: u32 = UNLOCKED,

        const UNLOCKED = 0;
        const LOCKED = 1;
        const WAKING = 1 << 8;
        const WAITING = 1 << 9;

        const Self = @This();

        pub fn acquire(self: *Self) void {
            // Fast-path acquire the lock (is most times inlined)
            const acquired = switch (builtin.arch) {
                // On x86, use "lock bts" since it has a smaller icache footprint.
                .i386, .x86_64 => atomic.bitSet(
                    &self.state,
                    @ctz(std.math.Log2Int(u32), LOCKED),
                    .Acquire,
                ) == 0,
                // On other architectures (currently only arm/aarch64) use weak CAS instead.
                // This is used over atomic.swap() to avoid doing a store() if contended
                // while spurious failure is handled by acquireSlow() below.
                else => atomic.tryCompareAndSwap(
                    @ptrCast(*u8, &self.state),
                    UNLOCKED,
                    LOCKED,
                    .Acquire,
                    .Relaxed,
                ) == null,
            };

            if (!acquired) {
                self.acquireSlow();
            }
        }

        fn acquireSlow(self: *Self) void {
            @setCold(true);

            var adaptive_spin: usize = 0;
            var state = atomic.load(&self.state, .Relaxed);
            while (true) {
                // If the lock is currently not held, try to acquire it.
                if (state & LOCKED == 0) {
                    const acquired = switch (builtin.arch) {
                        // On x86, use swap() instead of bitSet() or CAS as its faster under contention.
                        .i386, .x86_64 => atomic.swap(
                            @ptrCast(*u8, &self.state),
                            LOCKED,
                            .Acquire,
                        ) == UNLOCKED,
                        // On other archs (currently arm/aarch64) use a normal CAS instead of swap (see acquire()).
                        else => atomic.compareAndSwap(
                            @ptrCast(*u8, &self.state),
                            UNLOCKED,
                            LOCKED,
                            .Acquire,
                            .Relaxed,
                        ) == null,
                    };

                    if (acquired) {
                        return;
                    }

                    // If we failed to acquire the lock, this implies there is contention.
                    // If so, give up our thread's time quota to reschedule and try again.
                    // This serves to decrease atomic contention when dozens of threads are fighting for the lock.
                    windows.kernel32.Sleep(0);
                    state = atomic.load(&self.state, .Relaxed);
                    continue;
                }

                // If there are no waiting threads, try to spin a bit in hopes that the lock becomes unlocked.
                // Spinning instead of immediately sleeping helps in micro-contention cases when the lock is only
                // held for a small amount of time to avoid a syscall below.
                if ((state < WAITING) and yield(adaptive_spin)) {
                    adaptive_spin += 1;
                    state = atomic.load(&self.state, .Relaxed);
                    continue;
                }

                // Prepare our thread to wait by adding a waiter to the state.
                var new_state: u32 = undefined;
                if (@addWithOverflow(u32, state, WAITING, &new_state)) {
                    std.debug.panic("Too many waiters on a given NtLock", .{});
                }

                // Once we register our thread for waiting, then sleep using NtKeyedEvent.
                // A thread waking us up removes our WAITER from the state and sets the WAKING bit.
                // Upon waking, we unset the WAKING bit in order to allow another thread to wakeup.
                // This results in avoiding multiple threads waking up to compete on the lock and also backpressures syscalls.
                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    new_state,
                    .Relaxed,
                    .Relaxed,
                ) orelse blk: {
                    adaptive_spin = 0;
                    NtKeyedEvent.wait(&self.state, null) catch unreachable;
                    break :blk (atomic.fetchSub(&self.state, WAKING, .Relaxed) - WAKING);
                };
            }
        }

        pub fn release(self: *Self) void {
            // We unlock the Lock by zeroing out the LOCKED bit.
            // The LOCKED bit has its own byte which allows us to use a store() instead of RMW op.
            // The former is overall faster than the latter as LL/SC loops or bus-locked instructions are avoided.
            atomic.store(
                @ptrCast(*u8, &self.state),
                UNLOCKED,
                .Release,
            );

            // After unlocking, we need to see if we can wake up another thread to acquire the Lock.
            // We only attempt if there's any WAITERs and if theres not already a thread waking up (WAKING).
            // We also don't attempt to wake if the Lock was already acquired, as that thread will do the wakeup instead on next release().
            const state = atomic.load(&self.state, .Relaxed);
            if ((state >= WAITING) and (state & (LOCKED | WAKING) == 0)) {
                self.releaseSlow();
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);

            var state = atomic.load(&self.state, .Relaxed);
            while (true) {
                // Don't try to perform a wake up if:
                // - there are no threads waiting
                // - there's already a thread waking up
                // - the lock is currently acquired (that thread will do the wake up instead).
                if ((state < WAITING) or (state & (LOCKED | WAKING) != 0)) {
                    return;
                }

                // To wake up a waiter, we decrement one WAITER and set the WAKING bit.
                // This marks the waiting thread as "woken up" and prevents other waiting threads
                // from waking up until this one wakes up and unsets the WAKING bit.
                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    (state - WAITING) | WAKING,
                    .Relaxed,
                    .Relaxed,
                ) orelse {
                    NtKeyedEvent.wake(&self.state);
                    return;
                };
            }
        }
    };

    const NtEvent = struct {
        state: State,

        const Self = @This();
        const State = enum(u32) {
            empty,
            waiting,
            notified,
        };

        pub fn init(self: *Self) void {
            self.state = .empty;
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            self.state = .empty;
        }

        pub fn set(self: *Self) void {
            switch (atomic.swap(&self.state, .notified, .Release)) {
                .empty => return,
                .waiting => NtKeyedEvent.wake(@ptrCast(*const u32, &self.state)),
                .notified => unreachable, // multiple Event.set()'s performed.
            }
        }

        pub const Cancellation = u64;

        pub fn wait(self: *Self, deadline: ?u64) error{Cancelled}!void {
            // Try to mark the event as waiting if its not set.
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

            var timed_out = false;
            var timeout: ?u64 = null;
            if (deadline) |deadline_ns| {
                const now_ns = std.time.now();
                timed_out = now_ns > deadline_ns;
                if (!timed_out) {
                    timeout = deadline_ns - now_ns;
                }
            }

            if (!timed_out) {
                NtKeyedEvent.wait(
                    @ptrCast(*const u32, &self.state),
                    timeout,
                ) catch {
                    timed_out = true;
                };
            }

            // If we time out, we need to unmark the event as no longer waiting.
            // If we don't, then the set() thread will block on NtKeyedEvent and deadlock.
            //
            // Failing to unmark the event means that the set() thread is or will do a NtKeyedEvent.wake().
            // To prevent it from deadlocking, we do a matching NtKeyedEvent.wait() which should return almost immediately.
            if (timed_out) {
                const state = atomic.compareAndSwap(
                    &self.state,
                    .waiting,
                    .empty,
                    .Acquire,
                    .Acquire,
                ) orelse return error.TimedOut;
                assert(state == .notified);
                NtKeyedEvent.wait(
                    @ptrCast(*const u32, &self.state),
                    null,
                ) catch unreachable;
            }
        }
    };
};

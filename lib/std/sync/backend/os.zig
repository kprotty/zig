// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const assert = std.debug.assert;

pub usingnamespace if (builtin.os.tag == .windows)
    WindowsBackend
else if (builtin.os.tag == .linux)
    LinuxBackend
else if (std.Target.current.isDarwin() and DarwinBackend.is_supported)
    DarwinBackend
else if (builtin.link_libc)
    PosixBackend
else
    UnhandledOsBackend;

/// A ParkingLot backend which blocks the OS thread by falling back to std.time.sleep()
const UnhandledOsBackend = struct {
    // Unhandled OS, so nothing to optimize against.
    pub const bucket_count = 1;

    // Use the generic OS timing facilities
    pub const Timeout = OsTimeout;
    pub const Cancellation = OsCancellation;

    // Futex implementation which blocks via std.time.sleep()
    pub const Futex = struct {
        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
             while (true) {
                if (atomic.load(ptr, .SeqCst) != expected) {
                    return;
                }

                std.time.sleep(blk: {
                    if (cancellation) |cc| {
                        break :blk (cc.nanoseconds() orelse return error.Cancelled);
                    } else {
                        break :blk (1 * std.time.ns_per_ms);
                    }
                });
            }
        }

        pub fn notify(ptr: *const u32) void {
            // no-op
        }

        pub fn notifyAll(ptr: *const u32) void {
            // no-op
        }

        pub fn yield(iteration: usize) bool {
            return false;
        }
    };
};

/// A ParkingLot backend which blocks using linux futex
const LinuxBackend = struct {
    // Linux kernel's futex impl multiplies this by logical cpu core count.
    // We use tree based lookup instead of linked lists traversal for the
    // userspace implementation in ParkingLot so this is probably enough.
    pub const bucket_count = 256;
    
    // Use the generic OS timing facilities
    pub const Timeout = OsTimeout;
    pub const Cancellation = OsCancellation;

    // Futex implementation using the primiary target of the abstraction: linux futex.
    pub const CoreFutex = Futex;
    pub const Futex = struct {
        const linux = std.os.linux;

        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
            var ts: linux.timespec = undefined;
            var ts_ptr: ?*const linux.timespec = null;

            if (cancellation) |cc| {
                const timeout_ns = cc.nanoseconds() orelse return error.Cancelled;
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
                std.os.ETIMEDOUT => return error.Cancelled,
                else => |errno| {
                    const err = std.os.unexpectedErrno(errno);
                    unreachable;
                },
            }
        }

        pub inline fn notify(ptr: *const u32) void {
            return wake(ptr, 1);
        }

        pub inline fn notifyAll(ptr: *const u32) void {
            return wake(ptr, std.math.maxInt(i32));
        }

        fn wake(ptr: *const u32, num_waiters_to_wake: i32) void {
            switch (linux.getErrno(linux.futex_wake(
                @ptrCast(*const i32, ptr),
                linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAKE,
                num_waiters_to_wake,
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
            // Don't spin on low-power devices as the latency there is not worth the power draw
            switch (builtin.arch) {
                .i386, .x86_64, .sparc, sparcv9, .sparcel, .s390x => {},
                else => return false,
            }

            // On linux we don't use sched_yield...
            // https://www.realworldtech.com/forum/?threadid=189711&curpostid=189752
            //
            // As per the maximum spin count, it's the same as glibc:
            // https://elixir.bootlin.com/glibc/latest/source/sysdeps/generic/adaptive_spin_count.h
            //
            // But instead of static/single spins in glibc, we do spinning wih a backoff
            // as this appears to be faster throughput wise in various benchmarks.
            if (iteration < 10) {
                var spins = blk: {
                    const max_spins = 100;
                    const shift = @intCast(std.math.Log2Int(usize), iteration);
                    break :blk std.math.min(max_spins, @as(usize, 1) << shift);
                };
                while (spins > 0) : (spins -= 1) atomic.spinLoopHint();
                return true;
            }

            return false;
        }
    };
};

/// A ParkingLot backend which blocks using the undocumented __ulock functions for Darwin XNU.
const DarwinBackend = struct {
    // See: https://github.com/apple/darwin-libplatform/search?q=OS_UNFAIR_LOCK_AVAILABILITY
    const darwin = std.os.darwin;
    const version = std.Target.current.os.version_range.semver.min;
    const is_supported = switch (builtin.os.tag) {
        .macos => (version.major >= 10) and (version.minor >= 12),
        .ios => (version.major >= 10) and (version.minor >= 0),
        .tvos => (version.major >= 10) and (version.minor >= 0),
        .watchos => (version.major >= 3) and (version.minor >= 0),
        else => unreachable,
    };

    // Smaller bucket count to decrease current macho globals explosion
    pub const bucket_count = 64;

    // Use the generic OS timing facilities
    pub const Timeout = OsTimeout;
    pub const Cancellation = OsCancellation;

    // Futex implementation which blocks using the undocumented __ulock primitives.
    pub const CoreFutex = Futex;
    pub const Futex = struct {
        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
            // timeout = 0 indicates TIMEOUT_WAIT_FOREVER
            // https://github.com/apple/darwin-xnu/blob/main/bsd/kern/sys_ulock.c
            var timeout_us: u32 = 0;
            if (cancellation) |cc| {
                const timeout_ns = cc.nanoseconds() orelse return error.Cancelled;
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
                    darwin.ETIMEDOUT => return error.Cancelled,
                    else => |errno| {
                        const err = std.os.unexpectedErrno(@intCast(usize, errno));
                        unreachable;
                    },
                }
            }
        }

        pub inline fn notify(ptr: *const u32) void {
            return wake(ptr, 0);
        }

        pub inline fn notifyAll(ptr: *const u32) void {
            return wake(ptr, darwin.ULF_WAKE_ALL);
        }

        fn wake(ptr: *const u32, flags: u32) void {
            while (true) {
                const ret = darwin.__ulock_wake(
                    darwin.UL_COMPARE_AND_WAIT | darwin.ULF_NO_ERRNO | flags,
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

        pub fn yield(iteration: usize) bool {
            // Don't spin on the mobile platforms like iOS and watchOS 
            // as battery and avoiding priority inversion are worth more there.
            if (builtin.os.tag != .macos) {
                return false;
            }
            
            // After benchmarking on M1/BigSur, this appears to be a decent spin count for various cases.
            if (iteration < 5) {
                var spin = @as(usize, 8) << @intCast(std.math.Log2Int(usize), iteration);
                while (spin > 0) : (spin -= 1) atomic.spinLoopHint();
                return true;
            }

            return false;
        }
    };
};

/// A ParkingLot backend which blocks using pthread primitives
const PosixBackend = struct {
    // Generically sized bucket count which is often "good enough" (256 on 64bit, 128 on 32bit, etc.).
    // For 64bit, this boils down to about the same bucket count size used in linux-futex / Go-runtime.sema.
    pub const bucket_count = std.meta.bitCount(usize) << 2;

    // Use the generic OS timing facilities
    pub const Timeout = OsTimeout;
    pub const Cancellation = OsCancellation;

    // ParkingLot Event implementation which blocks the caller using pthread data structures.
    pub const Event = struct {
        state: State,
        cond: c.pthread_cond_t,
        mutex: c.pthread_mutex_t,
        
        const c = std.c;
        const Self = @This();
        const State = enum {
            empty,
            waiting,
            notified,
        };

        pub fn init(self: *Self) void {
            self.* = Self{
                .state = .empty,
                .cond = c.PTHREAD_COND_INITIALIZER,
                .mutex = c.PTHREAD_MUTEX_INITIALIZER,
            };
        }

        pub fn deinit(self: *Self) void {
            // On some BSD's like DragonflyBSD or NetBSD,
            // calling the _destroy() functions without using one of their methods
            // can result in it returning EINVAL from the _INITIALIZER constants.
            assertIn(c.pthread_mutex_destroy(&self.mutex), .{0, std.os.EINVAL});
            assertIn(c.pthread_cond_destroy(&self.cond), .{0, std.os.EINVAL});
        }

        pub fn reset(self: *Self) void {
            self.state = .empty;
        }

        pub fn set(self: *Self) void {
            assertIn(c.pthread_mutex_lock(&self.mutex), .{0});
            defer assertIn(c.pthread_mutex_unlock(&self.mutex), .{0});
        
            switch (self.state) {
                .empty => {
                    self.state = .notified;
                },
                .waiting => {
                    self.state = .notified;
                    assertIn(c.pthread_cond_signal(&self.cond), .{0});
                },
                .notified => {
                    unreachable; // PosixEvent.set() called multiple times
                },
            }
        }

        pub const Cancellation = SystemCancellation;

        pub fn wait(self: *Self, cancellation: ?*Cancellation) error{Cancelled}!void {
            assertIn(c.pthread_mutex_lock(&self.mutex), .{0});
            defer assertIn(c.pthread_mutex_unlock(&self.mutex), .{0});

            // Prepare to wait or bail upon noticing that the event is already set.
            switch (self.state) {
                .empty => self.state = .waiting,
                .waiting => unreachable, // multiple waiters on a PosixEvent
                .notified => return,
            }

            // Wait for the event to be set while sleeping on the pthread_cond_t.
            while (true) {
                switch (self.state) {
                    .empty => unreachable, // PosixEvent reset while still waiting
                    .waiting => {},
                    .notified => return,
                }

                const cc = cancellation orelse {
                    assertIn(c.pthread_cond_wait(&self.cond, &self.mutex), .{0});
                    continue;
                };

                const timeout = cc.nanoseconds() orelse return error.Cancelled;
                var timespec = timespecAfter(timeout);
                const rc = c.pthread_cond_timedwait(&self.cond, &self.mutex, &timespec);
                assertIn(rc, .{0, std.os.ETIMEDOUT});
            }
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

        /// Asserts that an rc is in the given "valid" tuple values.
        /// If not, reports the unknown rc and invokes illegal behavior.
        inline fn assertIn(rc: c_int, comptime valid: anytype) void {
            inline for (valid) |valid_rc| {
                if (rc == valid_rc) {
                    return;
                }
            }
            const err = std.os.unexpectedErrno(@intCast(usize, rc));
            unreachable;
        }

        /// Get an absolute timespec, with timeout into the future,
        /// which is used with pthread_cond_timedwait() to wait.
        fn timespecAfter(timeout: u64) std.os.timespec {
            var ts: std.os.timespec = undefined;
            const Sec = @TypeOf(ts.tv_sec);
            const Nsec = @TypeOf(ts.tv_nsec);

            // Get the timespec using the appropriate method
            if (comptime std.Target.current.isDarwin()) {
                var tv: std.os.timeval = undefined;
                std.os.gettimeofday(&tv, null);
                ts.tv_sec = tv.tv_sec;
                ts.tv_nsec = tv.tv_usec * std.time.ns_per_us;
            } else {
                std.os.clock_gettime(std.os.CLOCK_REALTIME, &ts) catch {
                    ts.tv_sec = std.math.maxInt(Sec);
                    ts.tv_nsec = std.time.ns_per_s - 1;
                };
            }
            
            // Add the timeout seconds to ts.tv_sec, saturating on overflow
            const tm_secs = std.math.cast(Sec, timeout / std.time.ns_per_s) catch std.math.maxInt(Sec);
            if (@addWithOverflow(Sec, ts.tv_sec, tm_secs, &ts.tv_sec)) {
                ts.tv_sec = std.math.maxInt(Sec);
            }

            // Add the timeout nanoseconds to ts.tv_nsec, overflowing into ts.tv_sec.
            var tm_nsec = @intCast(u64, ts.tv_nsec) + (timeout % std.time.ns_per_s);
            while (tm_nsec > std.time.ns_per_s) : (tm_nsec -= std.time.ns_per_s) {
                if (@addWithOverflow(Sec, ts.tv_sec, 1, &ts.tv_sec)) {
                    ts.tv_sec = std.math.maxInt(Sec);
                }
            }

            ts.tv_nsec = @intCast(Nsec, tm_nsec);
            return ts;
        }
    };
};

const WindowsBackend = struct {
    const windows = std.os.windows;

    /// Same size as windows.PEB.WaitOnAddressHashTable
    pub const bucket_count = 128;

    /// Use the OS cancellation object to keep the same API.
    pub const Cancellation = OsCancellation;

    /// ParkingLot Timeout implementation which is less precise than SystemTimeout but faster to query.
    pub const Timeout = struct {
        interrupt_time_100ns: u64 = 0,

        pub fn beFair(self: *@This(), fair_rng: u64) bool {
            const now = queryInterruptTime();
            if (now <= self.interrupt_time_100ns) {
                return false;
            }

            // Set the next expiry on the next KUSER_SHARED_DATA interrupt.
            // The interrupt has a granularity of 1ms to ~16ms depending on timeBeginPeriod/timeEndPeriod
            // which binds eventual fairness to the frequency of the system instead of the fixed 1ms.
            self.interrupt_time_100ns = now;
            return true;
        }

        fn queryInterruptTime() u64 {
            // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
            // https://golang.org/src/runtime/sys_windows_amd64.s
            const KUSER_SHARED_DATA = 0x7FFE0000;
            const INTERRUPT_TIME = KUSER_SHARED_DATA + 0x8;

            while (true) {
                // Must read user_high, then user_low, then kernel_high.
                // Snapshot is valid if user_high == kernel_high.
                // TODO: would switching to inexpensive volatile reads break ordering?
                const user_time_high = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 4), .SeqCst);
                const user_time_low = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 0), .SeqCst);
                const kernel_time_high = atomic.load(@intToPtr(*u32, INTERRUPT_TIME + 8), .SeqCst);

                if (user_time_high != kernel_time_high) {
                    atomic.spinLoopHint();
                    continue;
                }

                var interrupt_time = @as(u64, user_time_low);
                interrupt_time |= @as(u64, user_time_high) << 32;
                return interrupt_time;
            }
        }
    };

    /// ParkingLot.Event implementation backed by NtKeyedEvents
    pub const Event = struct {
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

        pub fn wait(self: *Self, cancellation: ?*Cancellation) error{Cancelled}!void {
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
            if (cancellation) |cc| {
                if (cc.nanoseconds()) |timeout_ns| {
                    timeout = timeout_ns;
                } else {
                    timed_out = true;
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
                ) orelse return error.Cancelled;
                assert(state == .notified);
                NtKeyedEvent.wait(
                    @ptrCast(*const u32, &self.state),
                    null,
                ) catch unreachable;
            }
        }

        pub fn yield(iteration: usize) bool {
            // Uses a similar spinning strategy to the one found in kernel32's CRITICAL_SECTION.
            // https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionandspincount
            if (iteration < 4000) {
                atomic.spinLoopHint();
                return true;
            }

            return false;
        }
    };

    pub usingnamespace if (SRWLock.is_supported)
        struct {
            pub const Lock = SRWLock;
            pub const CoreLock = SRWLock;
        }
    else struct {};

    const SRWLock = struct {
        srwlock: windows.SRWLOCK = windows.SRWLOCK_INIT,

        const Self = @This();
        const is_supported = std.Target.current.os.version_range.windows.isAtLeast(.vista) orelse false;

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn tryAcquire(self: *Self) ?Held {
            return switch (windows.kernel32.TryAcquireSRWLockExclusive(&self.srwlock)) {
                0 => null,
                else => Held{ .srwlock = &self.srwlock },
            };
        }

        pub fn acquire(self: *Self) Held {
            windows.kernel32.AcquireSRWLockExclusive(&self.srwlock);
            return Held{ .srwlock = &self.srwlock };
        }

        pub const Held = struct {
            srwlock: *windows.SRWLOCK,
            
            pub fn release(self: Held) void {
                windows.kernel32.ReleaseSRWLockExclusive(self.srwlock);
            }
        };
    };

    /// Windows NT Keyed Events API
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
};

/// A ParkingLot Timeout implementation which expires around every 1ms according to the OS.
const OsTimeout = struct {
    expires: u64 = 0,

    pub fn beFair(self: *OsTimeout, fair_rng: u64) bool {
        // Use std.time.Clock.Precise instead of std.time.now() 
        // since we don't really need the monotonic property here.
        const now = std.time.Clock.Precise.read() orelse 0;
        if (now < self.expires) {
            return false;
        }

        // Set the be_fair timer to expire after ~1ms in the future.
        const fair_after = 1 * std.time.ns_per_ms;
        const timeout = fair_rng % fair_after;
        self.expires = now + timeout;
        return true;
    }
};

/// The cancellation token used for OS based ParkingLot
const OsCancellation = union(enum) {
    Duration: u64,
    Deadline: u64,

    pub inline fn now() u64 {
        return std.time.now();
    }

    pub fn nanoseconds(self: *OsCancellation) ?u64 {
        const ts = OsCancellation.now();
        switch (self.*) {
            .Duration => |duration| {
                self.* = .{ .Deadline = ts + duration };
                return duration;
            },
            .Deadline => |deadline| {
                if (ts > deadline) return null;
                return deadline - ts;
            },
        }
    }
};
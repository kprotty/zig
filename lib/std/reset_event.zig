const std = @import("std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const Backoff = std.SpinLock.Backoff;
const c = std.c;
const os = std.os;
const time = std.time;
const linux = os.linux;
const windows = os.windows;

/// A resource object which supports blocking until signaled.
/// Once finished, the `deinit()` method should be called for correctness.
pub const ResetEvent = struct {
    os_event: OsEvent,

    pub fn init() ResetEvent {
        return ResetEvent{ .os_event = OsEvent.init() };
    }

    pub fn deinit(self: *ResetEvent) void {
        self.os_event.deinit();
        self.* = undefined;
    }

    /// Returns whether or not the event is currenetly set
    pub fn isSet(self: *ResetEvent) bool {
        return self.os_event.isSet();
    }
    
    /// Sets the event if not already set and wakes up at least one thread waiting the event.
    pub fn set(self: *ResetEvent) void {
        return self.os_event.set();
    }

    /// Resets the event to its original, unset state..
    pub fn reset(self: *ResetEvent) void {
        return self.os_event.reset();
    }

    /// Wait for the event to be set by blocking the current thread.
    pub fn wait(self: *ResetEvent) void {
        return self.os_event.wait(null) catch unreachable;
    }

    pub const WaitError = error{
        /// The thread blocked longer than the maximum time specified.
        TimedOut,
    };

    /// Wait for the event to be set by blocking the current thread.
    /// Supports passing a hint for the maximum amount of time spent waiting.
    /// When the thread has blocked longer than required, `WaitError.TimedOut` will be thrown.
    pub fn timedWait(self: *ResetEvent, timeout_ns: u64) WaitError!void {
        return self.os_event.wait(timeout_ns);
    }
};

const OsEvent = if (builtin.single_threaded) DebugEvent else switch (builtin.os) {
    .windows => WindowsEvent,
    .linux => if (builtin.link_libc) PosixEvent else LinuxEvent,
    else => if (builtin.link_libc) PosixEvent else SpinEvent,
};

const DebugEvent = struct {
    is_set: bool,

    pub fn init() DebugEvent {
        return DebugEvent{ .is_set = false };
    }

    pub fn deinit(self: *DebugEvent) void {
        self.* = undefined;
    }

    pub fn isSet(self: *DebugEvent) bool {
        return self.is_set;
    }

    pub fn set(self: *DebugEvent) void {
        self.is_set = true;
    }

    pub fn reset(self: *DebugEvent) void {
        self.is_set = false;
    }

    pub fn wait(self: *DebugEvent, timeout: ?u64) ResetEvent.WaitError!void {
        if (self.is_set)
            return;
        if (timeout != null)
            return ResetEvent.WaitError.TimedOut;
        @panic("deadlock detected");
    }
};

fn AtomicEvent(comptime FutexImpl: type) type {
    return struct {
        state: u32,

        const IS_SET: u32 = 1 << 0;
        const WAIT_MASK = ~IS_SET;

        pub const Self = @This();
        pub const Futex = FutexImpl;

        pub fn init() Self {
            return Self{ .state = 0 };
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn isSet(self: *const Self) bool {
            return @atomicLoad(u32, &self.state, .Acquire) == IS_SET;
        }

        pub fn reset(self: *Self) void {
            assert(@atomicLoad(u32, &self.state, .Monotonic) == IS_SET);
            @atomicStore(u32, &self.state, 0, .Monotonic);
        }

        pub fn set(self: *Self,) void {
            const old_state = @atomicRmw(u32, &self.state, .Xchg, IS_SET, .Release);
            if ((old_state & WAIT_MASK) != 0)
                Futex.wake(&self.state);
        }

        pub fn wait(self: *Self, timeout: ?u64) ResetEvent.WaitError!void {
            var dummy_value: u32 = undefined;
            const wait_token = @truncate(u32, @ptrToInt(&dummy_value));

            var state = @atomicLoad(u32, &self.state, .Monotonic);
            while (state != IS_SET) {
                state = @cmpxchgWeak(u32, &self.state, state, wait_token, .Acquire, .Monotonic) 
                    orelse return Futex.wait(&self.state, wait_token, timeout);
            }
        }
    };
}

const SpinEvent = AtomicEvent(struct {
    fn wake(ptr: *const u32) void {}

    fn wait(ptr: *const u32, expected: u32, timeout: ?u64) ResetEvent.WaitError!void {
        // TODO: handle platforms where time.Timer.start() fails
        var spin = Backoff.init();
        var timer = if (timeout == null) null else time.Timer.start() catch unreachable;
        while (@atomicLoad(u32, ptr, .Acquire) == expected) {
            spin.yield();
            if (timeout) |timeout_ns| {
                if (timer.?.read() > timeout_ns)
                    return ResetEvent.WaitError.TimedOut;
            }
        }
    }
});

const LinuxEvent = AtomicEvent(struct {
    fn wake(ptr: *const u32) void {
        const key = @ptrCast(*const i32, ptr);
        const rc = linux.futex_wake(key, linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG, 1);
        assert(linux.getErrno(rc) == 0);
    }

    fn wait(ptr: *u32, expected: u32, timeout: ?u64) ResetEvent.WaitError!void {
        var ts: linux.timespec = undefined;
        var ts_ptr: ?*linux.timespec = null;
        if (timeout) |timeout_ns| {
            ts_ptr = &ts;
            ts.tv_sec = @intCast(isize, timeout_ns / time.ns_per_s);
            ts.tv_nsec = @intCast(isize, timeout_ns % time.ns_per_s);
        }

        const key = @ptrCast(*const i32, ptr);
        const key_expect = @bitCast(i32, expected);
        while (@atomicLoad(i32, key, .Acquire) == key_expect) {
            const rc = linux.futex_wait(key, linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG, key_expect, ts_ptr);
            switch (linux.getErrno(rc)) {
                0, linux.EAGAIN => break,
                linux.EINTR => continue,
                linux.ETIMEDOUT => return ResetEvent.WaitError.TimedOut,
                else => unreachable,
            }
        }
    }
});

const WindowsEvent = AtomicEvent(struct {
    fn wake(ptr: *const u32) void {
        if (getEventHandle()) |handle| {
            const key = @ptrCast(*const c_void, ptr);
            // std.debug.warn("{} signalling\n", .{std.Thread.getCurrentId()});
            const rc = windows.ntdll.NtReleaseKeyedEvent(handle, key, windows.FALSE, null);
            // std.debug.warn("{} stopped signalling with {}\n", .{std.Thread.getCurrentId(), rc});
            assert(rc == 0);
        }
    }

    fn wait(ptr: *u32, expected: u32, timeout: ?u64) ResetEvent.WaitError!void {
        // fallback to spinlock if NT Keyed Events arent available
        const handle = getEventHandle() 
            orelse return SpinEvent.Futex.wait(ptr, expected, timeout);

        // NT uses timeouts in units of 100ns with negative value being relative
        var timeout_ptr: ?*windows.LARGE_INTEGER = null;
        var timeout_value: windows.LARGE_INTEGER = undefined;
        if (timeout) |timeout_ns| {
            timeout_ptr = &timeout_value;
            timeout_value = -@intCast(windows.LARGE_INTEGER, timeout_ns / 100);
        }

        // NtWaitForKeyedEvent doesnt have spurious wake-ups
        if (@atomicLoad(u32, ptr, .Acquire) == expected) {
            const key = @ptrCast(*const c_void, ptr);
            // std.debug.warn("{} waiting\n", .{std.Thread.getCurrentId()});
            var rc = windows.ntdll.NtWaitForKeyedEvent(handle, key, windows.FALSE, timeout_ptr);
            // std.debug.warn("{} stopped waiting with {}\n", .{std.Thread.getCurrentId(), rc});
            switch (rc) {
                windows.WAIT_OBJECT_0 => {},
                windows.WAIT_FAILED => unreachable,
                windows.WAIT_TIMEOUT => {
                    // If we dont reset the ptr, a thread calling `wake(ptr)` will
                    // assume that theres still a waiter and deadlock on NtReleaseKeyedEvent.
                    // Therefor, we restore any update done to ptr and block on
                    // NtWaitForKeyedEvent to match the corresponding NtReleaseKeyedEvent().
                    const current_ptr = @atomicRmw(u32, ptr, .Xchg, 0, .AcqRel);
                    if (current_ptr != expected) {
                        @atomicStore(u32, ptr, current_ptr, .Release);
                        rc = windows.ntdll.NtWaitForKeyedEvent(handle, key, windows.FALSE, null);
                        assert(rc == windows.WAIT_OBJECT_0);
                    }
                    return ResetEvent.WaitError.TimedOut;
                },
                else => unreachable,
            }
        }
    }

    var keyed_state = State.Uninitialized;
    var keyed_handle: ?windows.HANDLE = null;

    const State = enum(u32) {
        Uninitialized,
        Intializing,
        Initialized,
    };

    fn getEventHandle() ?windows.HANDLE {
        var spin = Backoff.init();
        var state = @atomicLoad(State, &keyed_state, .Monotonic);

        while (true) {
            switch (state) {
                .Initialized => {
                    return keyed_handle;
                },
                .Intializing => {
                    spin.yield();
                    state = @atomicLoad(State, &keyed_state, .Acquire);
                },
                .Uninitialized => state = @cmpxchgWeak(State, &keyed_state, state, .Intializing, .Acquire, .Monotonic) orelse {
                    var handle: windows.HANDLE = undefined;
                    const access_mask = windows.GENERIC_READ | windows.GENERIC_WRITE;
                    if (windows.ntdll.NtCreateKeyedEvent(&handle, access_mask, null, 0) == 0)
                        keyed_handle = handle;
                    @atomicStore(State, &keyed_state, .Initialized, .Release);
                    return keyed_handle;
                },
            }
        }
    }
});

const PosixEvent = struct {
    state: u32,
    cond: c.pthread_cond_t,
    mutex: c.pthread_mutex_t,

    const IS_SET: u32 = 1;

    pub fn init() PosixEvent {
        return PosixEvent{
            .state = .0,
            .cond = c.PTHREAD_COND_INITIALIZER,
            .mutex = c.PTHREAD_MUTEX_INITIALIZER,
        };
    }

    pub fn deinit(self: *PosixEvent) void {
        // On dragonfly, the destroy functions return EINVAL if they were initialized statically.
        const valid_error = if (builtin.os == .dragonfly) os.EINVAL else 0;

        const retm = c.pthread_mutex_destroy(&self.mutex);
        assert(retm == 0 or retm == valid_error);
        const retc = c.pthread_cond_destroy(&self.cond);
        assert(retc == 0 or retc == valid_error);
    }

    pub fn isSet(self: *PosixEvent) bool {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        return self.state == IS_SET;
    }

    pub fn reset(self: *PosixEvent) void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        self.state = 0;
    }

    pub fn set(self: *PosixEvent) void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        const had_waiter = self.state > IS_SET;
        self.state = IS_SET;
        if (had_waiter)
            assert(c.pthread_cond_signal(&self.cond) == 0);
    }

    pub fn wait(self: *PosixEvent, timeout: ?u64) ResetEvent.WaitError!void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        if (self.state == IS_SET)
            return;

        var ts: os.timespec = undefined;
        if (timeout) |timeout_ns| {
            var timeout_abs = timeout_ns;
            if (comptime std.Target.current.isDarwin()) {
                var tv: os.darwin.timeval = undefined;
                assert(os.darwin.gettimeofday(&tv, null) == 0);
                timeout_abs += @intCast(u64, tv.tv_sec) * time.second;
                timeout_abs += @intCast(u64, tv.tv_usec) * time.microsecond;
            } else {
                os.clock_gettime(os.CLOCK_REALTIME, &ts) catch unreachable;
                timeout_abs += @intCast(u64, ts.tv_sec) * time.second;
                timeout_abs += @intCast(u64, ts.tv_nsec);
            }
            ts.tv_sec = @intCast(@typeOf(ts.tv_sec), @divFloor(timeout_abs, time.second));
            ts.tv_nsec = @intCast(@typeOf(ts.tv_nsec), @mod(timeout_abs, time.second));
        }

        var dummy_value: u32 = undefined;
        var wait_token = @truncate(u32, @ptrToInt(&dummy_value));
        self.state = wait_token;

        while (self.state == wait_token) {
            const rc = switch (timeout == null) {
                true => c.pthread_cond_wait(&self.cond, &self.mutex),
                else => c.pthread_cond_timedwait(&self.cond, &self.mutex, &ts),
            };
            switch (rc) {
                0 => {},
                os.ETIMEDOUT => return ResetEvent.WaitError.TimedOut,
                os.EINVAL => unreachable,
                os.EPERM => unreachable,
                else => unreachable,
            }
        }
    }
};

test "std.ResetEvent" {
    var event = ResetEvent.init();
    defer event.deinit();

    // test event setting
    testing.expect(event.isSet() == false);
    event.set();
    testing.expect(event.isSet() == true);

    // test event resetting
    event.reset();
    testing.expect(event.isSet() == false);

    // test event waiting
    testing.expectError(error.TimedOut, event.timedWait(1));
    testing.expect(event.isSet() == false);
    event.set();
    try event.timedWait(1);

    // test cross-thread signaling
    if (builtin.single_threaded)
        return;

    const Context = struct {
        const Self = @This();
        const max_wait = 1 * time.second;

        value: u128,
        in: std.ResetEvent,
        out: std.ResetEvent,

        fn init() Self {
            return Self{
                .value = 0,
                .in = std.ResetEvent.init(),
                .out = std.ResetEvent.init(),
            };
        }

        fn deinit(self: *Self) void {
            self.in.deinit();
            self.out.deinit();
            self.* = undefined;
        }

        fn sender(self: *Self) !void {
            // update value and signal input
            testing.expect(self.value == 0);
            self.value = 1;
            self.in.set();

            // wait for receiver to update value and signal output
            try self.out.timedWait(max_wait);
            testing.expect(self.value == 2);
            
            // update value and signal final input
            self.value = 3;
            self.in.set();
        }

        fn receiver(self: *Self) void {
            // wait for sender to update value and signal input
            self.in.timedWait(max_wait) catch unreachable;
            assert(self.value == 1);
            
            // update value and signal output
            self.in.reset();
            self.value = 2;
            self.out.set();
            
            // wait for sender to update value and signal final input
            self.in.timedWait(max_wait) catch unreachable;
            assert(self.value == 3);
        }
    };

    var context = Context.init();
    defer context.deinit();
    const receiver = try std.Thread.spawn(&context, Context.receiver);
    defer receiver.wait();
    try context.sender();
}
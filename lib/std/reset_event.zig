const std = @import("std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const Backoff = std.SpinLock.Backoff;
const c = std.c;
const os = std.os;
const linux = os.linux;
const windows = os.windows;

pub const ResetEvent = switch (builtin.os) {
    .windows => AtomicEvent,
    else => if (builtin.link_libc) PosixEvent else AtomicEvent,
};

const PosixEvent = struct {
    is_set: bool,
    cond: c.pthread_cond_t,
    mutex: c.pthread_mutex_t,

    pub fn init() ResetEvent {
        return ResetEvent{
            .is_set = false,
            .cond = c.PTHREAD_COND_INITIALIZER,
            .mutex = c.PTHREAD_MUTEX_INITIALIZER,
        };
    }

    pub fn deinit(self: *ResetEvent) void {
        const valid_error = if (builtin.os == .dragonfly) os.EINVAL else 0;

        const retm = c.pthread_mutex_destroy(&self.mutex);
        assert(retm == 0 or retm == valid_error);
        const retc = c.pthread_cond_destroy(&self.cond);
        assert(retc == 0 or retc == valid_error);
    }

    pub fn reset(self: *ResetEvent) void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        self.is_set = false;
    }

    pub fn set(self: *ResetEvent) void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        if (!self.is_set) {
            self.is_set = true;
            assert(c.pthread_cond_signal(&self.cond) == 0);
        }
    }

    pub fn wait(self: *ResetEvent) void {
        assert(c.pthread_mutex_lock(&self.mutex) == 0);
        defer assert(c.pthread_mutex_unlock(&self.mutex) == 0);

        while (!self.is_set)
            assert(c.pthread_cond_wait(&self.cond, &self.mutex) == 0);
    }
};

const AtomicEvent = struct {
    key: i32,
    os_event: OsEvent,
 
    pub fn init() ResetEvent {
        return ResetEvent{
            .key = 0,
            .os_event = OsEvent.init(),
        };
    }
 
    pub fn deinit(self: *ResetEvent) void {
        self.os_event.deinit();
        self.* = undefined;
    }
 
    pub fn reset(self: *ResetEvent) void {
        @atomicStore(i32, &self.key, 0, .Release);
    }
 
    pub fn set(self: *ResetEvent) void {
        if (@atomicRmw(i32, &self.key, .Xchg, 2, .Release) == 1)
            self.os_event.wake(&self.key);
    }
 
    pub fn wait(self: *ResetEvent) void {
        var state = @atomicLoad(i32, &self.key, .Monotonic);
        while (state == 0) {
            state = @cmpxchgWeak(i32, &self.key, 0, 1, .Acquire, .Monotonic) orelse {
                self.os_event.wait(&self.key);
                return;
            };
        }
    }
 
    const OsEvent = switch (builtin.os) {
        .windows => WindowsEvent,
        .linux => LinuxEvent,
        else => SpinEvent,
    };
 
    const SpinEvent = struct {
        fn init() SpinEvent {
            return SpinEvent{};
        }

        fn deinit(self: *SpinEvent) void {}
 
        fn wake(self: *SpinEvent, ptr: *i32) void {}

        fn wait(self: *SpinEvent, ptr: *i32) void {
            var spin = Backoff.init();
            while (@atomicLoad(i32, ptr, .Acquire) == 1)
                spin.yield();
        }
    };
 
    const LinuxEvent = struct {
        fn init() LinuxEvent {
            return LinuxEvent{};
        }

        fn deinit(self: *LinuxEvent) void {}
 
        fn wake(self: *LinuxEvent, ptr: *i32) void {
            const rc = linux.futex_wake(ptr, linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG, 1);
            assert(os.errno(rc) == 0);
        }
 
        fn wait(self: *LinuxEvent, ptr: *i32) void {
            while (@atomicLoad(i32, ptr, .Acquire) == 1) {
                const rc = linux.futex_wait(ptr, linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG, 1, null);
                switch (os.errno(rc)) {
                    0 => return,
                    os.EAGAIN => return,
                    os.EINTR => continue,
                    else => unreachable,
                }
            }
        }
    };

    const WindowsEvent = struct {
        fn init() WindowsEvent {
            return WindowsEvent{};
        }

        fn deinit(self: *WindowsEvent) void {}
 
        fn wake(self: *WindowsEvent, ptr: *i32) void {
            const handle = getEventHandle() orelse return @ptrCast(*SpinEvent, self).wake(ptr);
            const key = @ptrCast(*const c_void, ptr);
            const rc = windows.ntdll.NtReleaseKeyedEvent(handle, key, windows.FALSE, null);
            assert(rc == 0);
        }
 
        fn wait(self: *WindowsEvent, ptr: *i32) void {
            const handle = getEventHandle() orelse return @ptrCast(*SpinEvent, self).wait(ptr);
            const key = @ptrCast(*const c_void, ptr);
            const rc = windows.ntdll.NtWaitForKeyedEvent(handle, key, windows.FALSE, null);
            assert(rc == 0);
        }
 
        var event_handle = std.lazyInit(?windows.HANDLE);
 
        fn getEventHandle() ?windows.HANDLE {
            if (event_handle.get()) |handle|
                return handle.*;
            const handle_ptr = @ptrCast(*windows.HANDLE, &event_handle.data);
            const access_mask = windows.GENERIC_READ | windows.GENERIC_WRITE;
            if (windows.ntdll.NtCreateKeyedEvent(handle_ptr, access_mask, null, 0) != 0)
                event_handle.data = null;
            event_handle.resolve();
            return event_handle.data;
        }
    };
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

    // test cross-thread signaling
    if (builtin.single_threaded)
        return;

    const Context = struct {
        const Self = @This();

        value: u128,
        in: ResetEvent,
        out: ResetEvent,

        fn init() Self {
            return Self{
                .value = 0,
                .in = ResetEvent.init(),
                .out = ResetEvent.init(),
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
            self.out.wait();
            testing.expect(self.value == 2);
            
            // update value and signal final input
            self.value = 3;
            self.in.set();
        }

        fn receiver(self: *Self) void {
            // wait for sender to update value and signal input
            self.in.wait();
            assert(self.value == 1);
            
            // update value and signal output
            self.in.reset();
            self.value = 2;
            self.out.set();
            
            // wait for sender to update value and signal final input
            self.in.wait();
            assert(self.value == 3);
        }
    };

    var context = Context.init();
    defer context.deinit();
    const receiver = try std.Thread.spawn(&context, Context.receiver);
    defer receiver.wait();
    try context.sender();
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const os = std.os;
const Allocator = std.mem.Allocator;

pub const Reactor = PosixReactor(switch (builtin.os) {
    .linux => struct {
        pub fn init() !os.fd_t {
            return os.epoll_create1(os.EPOLL_CLOEXEC);
        }

        pub fn register(poll_fd: os.fd_t, fd: os.fd_t, data: usize) !void {
            try os.epoll_ctl(poll_fd, os.EPOLL_CTL_ADD, fd, &os.epoll_event{
                .events = os.EPOLLIN | os.EPOLLOUT | os.EPOLLET,
                .data = os.epoll_data{ .ptr = data },
            });
        }

        pub const Event = extern struct {
            inner: os.epoll_event,

            pub fn getData(self: Event) usize {
                return self.inner.data.ptr;
            }
        };

        pub fn poll(poll_fd: os.fd_t, events: []Event, timeout_ms: ?u32) usize {
            return os.epoll_wait(
                poll_fd,
                @ptrCast([*]os.epoll_event, events.ptr)[0..events.len],
                if (timeout_ms) |t| @intCast(i32, t) else -1
            );
        }
    },
    .macosx, .freebsd, .netbsd, .dragonfly => struct {
        pub fn init() !os.fd_t {
            return os.kqueue();
        }

        pub fn register(poll_fd: os.fd_t, fd: os.fd_t, data: usize) !void {
            var events: [2]os.Kevent = undefnied;
            events[0] = os.Kevent{
                .ident = fd,
                .filter = os.EVFILT_READ,
                .flags = os.EV_ADD | os.EV_CLEAR,
                .fflags = 0,
                .data = 0,
                .udata = data,
            };
            events[1] = events[0];
            events[1].filter = os.EVFILT_WRITE;
            const empty_events = @as([*]os.Kevent, undefined)[0..0];
            _ = try os.kevent(poll_fd, events[0..], empty_events, null);
        }

        pub const Event = extern struct {
            inner: os.Kevent,

            pub fn getData(self: Event) usize {
                return self.inner.udata;
            }
        };

        pub fn poll(poll_fd: os.fd_t, events: []Event, timeout_ms: ?u32) usize {
            var ts: os.timespec = undefined;
            var ts_ptr: ?*const os.timespec = null;
            if (timeout_ms) |timeout| {
                ts_ptr = &ts;
                const timeout_ns = timeout * std.time.millisecond;
                ts.tv_sec = @intCast(isize, timeout_ns / std.time.ns_per_s);
                ts.tv_nsec = @intCast(isize, timeout_ns % std.time.ns_per_s);
            }

            return os.kevent(
                poll_fd,
                @as([*]os.Kevent, undefined)[0..0],
                @ptrCast([*]os.Kevent, events.ptr)[0..events.len],
                ts_ptr,
            ) catch unreachable;
        }
    },
    else => @compileError("OS not supported"),
});

fn PosixReactor(comptime NativePoller: type) type {
    return struct {
        const Self = @This();

        fd: os.fd_t,

        pub fn init(self: *Self, allocator: ?*Allocator) !void {
            self.fd = try NativePoller.init();
        }

        pub fn deinit(self: *Self) void {
            os.close(self.fd);
        }
    };
}

const std = @import("../../std.zig");
const builtin = @import("builtin");
const posix = @import("./posix.zig");
const Allocator = std.mem.Allocator;
const PosixReactor = posix.Reactor;

pub const Reactor = union(enum) {
    uring: UringReactor,
    posix: PosixReactor,

    pub fn init(self: *Reactor, allocator: ?*Allocator) !void {
        if (UringReactor.isSupported()) {
            self.* = .{ .uring = undefined };
            try self.uring.init(allocator);
        } else {
            self.* = .{ .posix = undefined };
            try self.posix.init(allocator);
        }
    }

    pub fn deinit(self: *Reactor) void {
        return switch (self.*) {
            .uring => |uring| uring.deinit(),
            .posix => |posix| posix.deinit(),
        };
    }
};

const UringReactor = struct {

    fn isSupported() bool {
        // TODO
        return false;
    }

    fn init(self: *UringReactor) !void {
        return error.Todo;
    }

    fn deinit(self: *UringReactor) void {
        // TODO
    }
};


const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;

/// Thread-safe initialization of global data.
pub fn lazyInit(comptime T: type) LazyInit(T) {
    return LazyInit(T){
        .data = undefined,
    };
}

fn LazyInit(comptime T: type) type {
    return struct {
        lock: std.Mutex = std.Mutex.init(),
        is_resolved: u8 = 0,
        data: Data,

        const Self = @This();

        // TODO this isn't working for void, investigate and then remove this special case
        const Data = if (@sizeOf(T) == 0) u8 else T;
        const Ptr = if (T == void) void else *T;

        /// Returns a usable pointer to the initialized data,
        /// or returns null, indicating that the caller should
        /// perform the initialization and then call resolve().
        pub fn get(self: *Self) ?Ptr {
            if (@atomicLoad(u8, &self.is_resolved, .Monotonic) == 0) {
                const held = self.lock.acquire();
                if (self.is_resolved == 0)
                    return null;
                held.release();
            }
            
            if (@sizeOf(T) == 0) {
                return @as(T, undefined);
            } else {
                return &self.data;
            }
        }

        pub fn resolve(self: *Self) void {
            const held = std.Mutex.Held{ .mutex = &self.lock };
            @atomicStore(u8, &self.is_resolved, 1, .Monotonic);
            held.release();
        }
    };
}

var global_number = lazyInit(i32);

test "std.lazyInit" {
    if (global_number.get()) |_| @panic("bad") else {
        global_number.data = 1234;
        global_number.resolve();
    }
    if (global_number.get()) |x| {
        testing.expect(x.* == 1234);
    } else {
        @panic("bad");
    }
    if (global_number.get()) |x| {
        testing.expect(x.* == 1234);
    } else {
        @panic("bad");
    }
}

var global_void = lazyInit(void);

test "std.lazyInit(void)" {
    if (global_void.get()) |_| @panic("bad") else {
        global_void.resolve();
    }
    testing.expect(global_void.get() != null);
    testing.expect(global_void.get() != null);
}

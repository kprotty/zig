const std = @import("std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const ResetEvent = std.ResetEvent;

/// Lock may be held only once. If the same thread
/// tries to acquire the same mutex twice, it deadlocks.
/// This type supports static initialization and is based off of Webkit's WTF Lock (via rust parking_lot)
/// https://github.com/Amanieu/parking_lot/blob/master/core/src/word_lock.rs
/// When an application is built in single threaded release mode, all the functions are
/// no-ops. In single threaded debug mode, there is deadlock detection.
pub const Mutex = if (builtin.single_threaded)
    struct {
        lock: @typeOf(lock_init),

        const lock_init = if (std.debug.runtime_safety) false else {};

        pub const Held = struct {
            mutex: *Mutex,

            pub fn release(self: Held) void {
                if (std.debug.runtime_safety) {
                    self.mutex.lock = false;
                }
            }
        };
        pub fn init() Mutex {
            return Mutex{ .lock = lock_init };
        }
        pub fn deinit(self: *Mutex) void {}

        pub fn acquire(self: *Mutex) Held {
            if (std.debug.runtime_safety and self.lock) {
                @panic("deadlock detected");
            }
            return Held{ .mutex = self };
        }
    }
else
    struct {
        state: usize,
    
        const MUTEX_LOCK: usize = 1;
        const QUEUE_LOCK: usize = 2;
        const QUEUE_MASK: usize = ~(MUTEX_LOCK | QUEUE_LOCK);
    
        const SPIN_CPU = 4;
        const SPIN_CPU_COUNT = 30;
        const SPIN_THREAD = 1;
    
        const QueueNode = struct {
            next: ?*QueueNode,
            event: ResetEvent,
        };
    
        pub fn init() Mutex {
            return Mutex{ .state = 0 };
        }
    
        pub fn deinit(self: *Mutex) void {
            self.* = undefined;
        }
    
        pub fn acquire(self: *Mutex) Held {
            if (@cmpxchgWeak(usize, &self.state, 0, MUTEX_LOCK, .Acquire, .Monotonic)) |state|
                self.acquireSlow();
            return Held{ .mutex = self };
        }
    
        fn acquireSlow(self: *Mutex) void {
            var spin_count: usize = 0;
            var state = @atomicLoad(usize, &self.state, .Monotonic);
            while (true) {
    
                if (state & MUTEX_LOCK == 0) {
                    state = @cmpxchgWeak(usize, &self.state, state, state | MUTEX_LOCK, .Acquire, .Monotonic) orelse return;
                    continue;
                }
    
                if (state & QUEUE_MASK == 0 and spin_count < SPIN_CPU + SPIN_THREAD) {
                    if (spin_count < SPIN_CPU) {
                        std.SpinLock.yield(SPIN_CPU_COUNT);
                    } else {
                        std.os.sched_yield() catch std.time.sleep(1 * std.time.millisecond);
                    }
                    spin_count += 1;
                    state = @atomicLoad(usize, &self.state, .Monotonic);
                    continue;
                }
    
                var node = QueueNode{
                    .event = ResetEvent.init(),
                    .next = @intToPtr(?*QueueNode, state & QUEUE_MASK),
                };
                defer node.event.deinit();
                const new_state = @ptrToInt(&node) | (state & ~QUEUE_MASK);
                state = @cmpxchgWeak(usize, &self.state, state, new_state, .Release, .Monotonic) orelse {
                    node.event.wait();
                    spin_count = 0;
                    state = @atomicLoad(usize, &self.state, .Monotonic);
                    continue;
                };
            }
        }
    
        pub const Held = struct {
            mutex: *Mutex,
    
            pub fn release(self: Held) void {
                const state = @atomicRmw(usize, &self.mutex.state, .Sub, MUTEX_LOCK, .Release);
                if (state & QUEUE_LOCK == 0 and state & QUEUE_MASK != 0)
                    self.mutex.releaseSlow();
            }
        };
    
        fn releaseSlow(self: *Mutex) void {
            var state = @atomicLoad(usize, &self.state, .Monotonic);
            while (true) {
                if (state & QUEUE_LOCK != 0 or state & QUEUE_MASK == 0)
                    return;
                state = @cmpxchgWeak(usize, &self.state, state, state | QUEUE_LOCK, .Acquire, .Monotonic) orelse break;
            }

            state = @atomicLoad(usize, &self.state, .Monotonic);
            while (true) {
                if (state & MUTEX_LOCK != 0) {
                    state = @cmpxchgWeak(usize, &self.state, state, state & ~QUEUE_LOCK, .Release, .Monotonic) orelse return;
                    continue;
                }

                @fence(.Acquire);
                const node = @intToPtr(*QueueNode, state & QUEUE_MASK);
                state = @cmpxchgWeak(usize, &self.state, state, @ptrToInt(node.next), .Release, .Monotonic) orelse {
                    node.event.set();
                    return;
                };
            }
        }
    };

const TestContext = struct {
    mutex: *Mutex,
    data: i128,

    const incr_count = 10000;
};

test "std.Mutex" {
    var plenty_of_memory = try std.heap.page_allocator.alloc(u8, 300 * 1024);
    defer std.heap.page_allocator.free(plenty_of_memory);

    var fixed_buffer_allocator = std.heap.ThreadSafeFixedBufferAllocator.init(plenty_of_memory);
    var a = &fixed_buffer_allocator.allocator;

    var mutex = Mutex.init();
    defer mutex.deinit();

    var context = TestContext{
        .mutex = &mutex,
        .data = 0,
    };

    if (builtin.single_threaded) {
        worker(&context);
        testing.expect(context.data == TestContext.incr_count);
    } else {
        const thread_count = 10;
        var threads: [thread_count]*std.Thread = undefined;
        for (threads) |*t| {
            t.* = try std.Thread.spawn(&context, worker);
        }
        for (threads) |t|
            t.wait();

        testing.expect(context.data == thread_count * TestContext.incr_count);
    }
}

fn worker(ctx: *TestContext) void {
    var i: usize = 0;
    while (i != TestContext.incr_count) : (i += 1) {
        const held = ctx.mutex.acquire();
        defer held.release();

        ctx.data += 1;
    }
}

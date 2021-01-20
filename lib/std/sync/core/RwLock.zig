// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const helgrind = std.valgrind.helgrind;
const use_valgrind = std.builtin.valgrind_support;

pub fn RwLock(comptime parking_lot: type) type {
    // TODO: better implementation which doesn't rely on Mutex + Semaphore
    return extern struct {
        state: usize = 0,
        mutex: Mutex = .{},
        semaphore: Semaphore = .{},

        const IS_WRITING = 1;
        const WRITER = 1 << 1;
        const READER = 1 << (1 + std.meta.bitCount(Count));
        const WRITER_MASK = std.math.maxInt(Count) << @ctz(usize, WRITER);
        const READER_MASK = std.math.maxInt(Count) << @ctz(usize, READER);
        const Count = std.meta.Int(.unsigned, @divFloor(std.meta.bitCount(usize) - 1, 2));

        const Self = @This();
        const Mutex = @import("./Mutex.zig").Mutex(parking_lot);
        const Semaphore = @import("./Semaphore.zig").Semaphore(parking_lot);

        pub fn tryAcquire(self: *Self) ?Held {
            if (self.mutex.tryAcquire()) |held| {
                const state = atomic.load(&self.state, .SeqCst);

                if (state & READER_MASK == 0) {
                    _ = atomic.bitSet(&self.state, @ctz(u3, IS_WRITING), .SeqCst);

                    if (use_valgrind) {
                        helgrind.annotateHappensAfter(@ptrToInt(self));
                    }

                    return Held{
                        .held = held,
                        .rwlock = self,
                    };
                }

                held.release();
            }

            return null;
        }

        pub fn acquire(self: *Self) Held {
            return self.acquireInner(null) catch unreachable;
        }

        pub fn tryAcquireFor(self: *Self, duration: u64) error{TimedOut}!Held {
            return self.tryAcquireUntil(parking_lot.nanotime() + duration);
        }

        pub fn tryAcquireUntil(self: *Self, deadline: u64) error{TimedOut}!Held {
            return self.acquireInner(deadline);
        }

        fn acquireInner(self: *Self, deadline: ?u64) error{TimedOut}!Held {
            _ = atomic.fetchAdd(&self.state, WRITER, .SeqCst);
            const held = self.mutex.acquire();

            const state = atomic.fetchAdd(&self.state, IS_WRITING, .SeqCst);
            if (state & READER_MASK != 0) {
                if (deadline) |deadline_ns| {
                    self.semaphore.tryWaitUntil(deadline) catch {
                        _ = atomic.bitUnset(&self.state, @ctz(u3, IS_WRITING), .SeqCst);
                        held.release();
                        return error.TimedOut;
                    };
                } else {
                    self.semaphore.wait();
                }
            }

            if (use_valgrind) {
                helgrind.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{
                .held = held,
                .rwlock = self,
            };
        }

        pub fn tryAcquireShared(self: *Self) ?Held {
            const held = blk: {
                var state = atomic.load(&self.state, .SeqCst);
                if (state & (IS_WRITING | WRITER_MASK) == 0) {
                    _ = atomic.compareAndSwap(
                        &self.state,
                        state,
                        state + READER,
                        .SeqCst,
                        .SeqCst,
                    ) orelse break :blk Held{
                        .held = null,
                        .rwlock = self,
                    };
                }

                if (self.mutex.tryAcquire()) |held| {
                    _ = atomic.fetchAdd(&self.state, READER, .SeqCst);
                    held.release();

                    break :blk Held{
                        .held = null,
                        .rwlock = self,
                    };
                }

                return null;
            };

            if (use_valgrind) {
                helgrind.annotateHappensAfter(@ptrToInt(self));
            }

            return held;
        }

        pub fn acquireShared(self: *Self) Held {
            return self.acquireSharedInner(null) catch unreachable;
        }

        pub fn tryAcquireSharedFor(self: *Self, duration: u64) error{TimedOut}!Held {
            return self.tryAcquireSharedUntil(parking_lot.nanotime() + duration);
        }

        pub fn tryAcquireSharedUntil(self: *Self, deadline: u64) error{TimedOut}!Held {
            return self.acquireSharedInner(deadline);
        }
        
        pub fn acquireSharedInner(self: *Self, deadline: ?u64) error{TimedOut}!Held {
            var state = atomic.load(&self.state, .SeqCst);
            while (state & (IS_WRITING | WRITER_MASK) == 0) {
                _ = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    state + READER,
                    .SeqCst,
                    .SeqCst,
                ) orelse return Held{
                    .held = null,
                    .rwlock = self,
                };
            }

            const held = blk: {
                if (deadline) |deadline_ns|
                    break :blk try self.mutex.tryAcquireUntil(deadline_ns);
                break :blk self.mutex.acquire();
            };
            _ = atomic.fetchAdd(&self.state, READER, .SeqCst);
            held.release();

            if (use_valgrind) {
                helgrind.annotateHappensAfter(@ptrToInt(self));
            }
            
            return Held{
                .held = null,
                .rwlock = self,
            };
        }

        pub const Held = struct {
            rwlock: *Self,
            held: ?Mutex.Held,

            pub fn release(self: Held) void {
                if (use_valgrind) {
                    helgrind.annotateHappensBefore(@ptrToInt(self));
                }
                
                if (self.held) |held| {
                    self.rwlock.release(held);
                } else {
                    self.rwlock.releaseShared();
                }
            }
        };

        fn release(self: *Self, held: Mutex.Held) void {
            _ = atomic.bitUnset(&self.state, @ctz(u3, IS_WRITING), .SeqCst);
            held.release();
        }

        fn releaseShared(self: *Self) void {
            const state = atomic.fetchSub(&self.state, READER, .SeqCst);

            if ((state & READER_MASK == READER) and (state & IS_WRITING != 0))
                self.semaphore.post();
        }
    };
}

pub const DebugRwLock = extern struct {
    state: usize = 0,

    const Self = @This();
    const WRITER: usize = 1 << 0;
    const READER: usize = 1 << 1;

    pub fn tryAcquire(self: *Self) ?Held {
        if (self.state != 0)
            return null;

        self.state = WRITER;
        return Held{
            .rwlock = self,
            .sub = WRITER,
        };
    }

    pub fn acquire(self: *Self) Held {
        return self.tryAcquire() orelse @panic("deadlock detected");
    }

    pub fn tryAcquireFor(self: *Self, duration: u64) error{TimedOut}!Held {
        return self.acquire();
    }

    pub fn tryAcquireUntil(self: *Self, deadline: u64) error{TimedOut}!Held {
        return self.acquire();
    }

    pub fn tryAcquireShared(self: *Self) ?Held {
        if (self.state & WRITER != 0)
            return null;

        self.state += READER;
        return Held{
            .rwlock = self,
            .sub = READER,
        };
    }

    pub fn acquireShared(self: *Self) Held {
        return self.tryAcquireShared() orelse @panic("deadlock detected");
    }

    pub fn tryAcquireSharedFor(self: *Self, duration: u64) error{TimedOut}!Held {
        return self.acquireShared();
    }

    pub fn tryAcquireSharedUntil(self: *Self, deadline: u64) error{TimedOut}!Held {
        return self.acquireShared();
    }

    pub const Held = struct {
        rwlock: *Self,
        sub: usize,

        pub fn release(self: Held) void {
            self.rwlock.state -= self.sub;
        }
    };
};
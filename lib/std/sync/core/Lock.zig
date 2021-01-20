// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");
const builtin = std.builtin;
const testing = std.testing;

const helgrind = std.valgrind.helgrind;
const use_valgrind = builtin.valgrind_support;

/// This is an unfair mutex lock implementation inspired by:
///  - parking_lot's WordLock: https://github.com/Amanieu/parking_lot/blob/master/core/src/word_lock.rs
///  - locklessinc's KeyedLock: http://www.locklessinc.com/articles/keyed_events/
///
/// [  remaining: uX   | is_waking: u1 |  ignored: u7  | is_locked: u1 ]: usize
///
/// - is_locked:
///     When set, indicates that the lock is currently owned.
///     Because it is only one bit, this allows an x86 optimization to use `lock bts` for acquire.
///
/// - ignored:
///     These bits are ignored and used to effectively pad the `is_locked` bit to 8-bits/1-byte.
///     Having the `is_locked` bit in its own byte is a two-fold optimization:
///
///         Acquiring the lock for non x86 platforms can swap the entire u8 instead of a CAS on the whole usize.
///         This means that it does not have to compete with other waiters trying to CAS the whole usize.
///
///         Releasing the lock for all platforms is an atomic u8 store to the is_locked byte.
///         This means that unlocking on most platforms should require almost no (retry) synchronization.
///
/// - is_waking:
///     When set, indicates that there is a waiter being woken up.
///     One release() thread will set this bit when trying to perform a wake up (while others can keep acquiring).
///     Once the waiter is woken up by the release() thread, the waiter will unset the is_waking bit themselves.
///     These have the effect of throttling wake-up in favor of throughput with the idea that a wake-up is expensive.
///
/// - remaining:
///     The remaining of the usize bits represent the head Waiter pointer for the wait queue.
///     The queue is dequeued for Waiters in a FIFO ordering to avoid having to update the head (hence state) when contended.
///     The Waiter must then be aligned higher than the `is_waking` bit above in order for its lower bits to be used to encode the other states.
pub fn Lock(comptime config: anytype) type {
    const Event = config.Event;

    const byte_swap = switch (@hasDecl(config, "byte_swap")) {
        true => config.byte_swap,
        else => false,
    };

    return extern struct {
        state: usize = UNLOCKED,

        const UNLOCKED = 0;
        const LOCKED = 1 << 0;
        const WAKING = 1 << (if (byte_swap) 8 else 2);
        const WAITING = ~@as(usize, (WAKING << 1) - 1); // aligned past WAKING

        const Waiter = struct {
            prev: ?*Waiter align(std.math.max(@alignOf(usize), ~WAITING + 1)),
            next: ?*Waiter,
            tail: ?*Waiter,
            event: Event,
        };

        pub fn deinit(self: *Self) void {
            if (use_valgrind) {
                helgrind.annotateHappensBeforeForgetAll(@ptrToInt(self));
            }

            self.* = undefined;
        }

        /// Try to acquire the lock if its unlocked.
        pub fn tryAcquire(self: *Lock) bool {
            const acquired = self.tryAcquireFast(UNLOCKED);

            if (use_valgrind and acquired) {
                helgrind.annotateHappensAfter(@ptrToInt(self));
            }

            return acquired;
        }

        /// Acquire ownership of the Lock, using the Event to implement blocking.
        pub fn acquire(self: *Lock) void {
            if (!self.tryAcquire()) {
                self.acquireSlow();
            }

            if (use_valgrind) {
                helgrind.annotateHappensAfter(@ptrToInt(self));
            }
        }

        inline fn tryAcquireFast(self: *Lock, current_state: usize) bool {
            // On x86, its better to use `lock bts` over `lock xchg`
            // as the former requires less instructions (lock-bts, jz)
            // over the latter (mov-reg-1, xchg, test, jz).
            //
            // For the fast path when there's no contention,
            // This helps in decreasing the hit on the instruction cache
            // ever so slightly but is seen to help in benchmarks.
            if (builtin.arch == .i386 or .arch == .x86_64) {
                return atomic.bitSet(
                    &self.state,
                    @ctz(u1, LOCKED),
                    .Acquire
                ) == UNLOCKED;
            }
            
            if (byte_swap) {
                return atomic.swap(
                    @ptrCast(*u8, self.state),
                    LOCKED,
                    .Acquire,
                ) == UNLOCKED;
            }

            var state = current_state;
            while (true) {
                if (state & LOCKED != 0)
                    return false;
                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    state | LOCKED,
                    .Acquire,
                    .Relaxed,
                ) orelse return true;
            }
        }

        fn acquireSlow(self: *Lock) void {
            @setCold(true);

            // The waiter for this thread is allocated on it's stack.
            var waiter: Waiter = undefined;

            // Use lazy initialization for the event
            var has_event = false;
            defer if (has_event) 
                waiter.event.deinit();

            var spin_iter: usize = 0;
            var state = atomic.load(&self.state, .relaxed);
            while (true) {
                
                // Try to acquire the lock if its unlocked.
                if (state & LOCKED == 0) {
                    if (self.tryAcquireFast(state))
                        return;

                    _ = Event.yield(null);
                    state = atomic.load(&self.state, .relaxed);
                    continue;
                }
                
                // If its locked, spin on it using the Event if theres no waiters.
                const head = @intToPtr(?*Waiter, state & WAITING);
                if (head == null and Event.yield(spin_iter)) {
                    spin_iter +%= 1;
                    state = atomic.load(&self.state, .relaxed);
                    continue;
                }
                
                // The lock is contended, prepare our waiter to be enqueued at the head.
                // The first waiter to be enqueued sets its tail to itself.
                //  This is needed later in release().
                const waiter = &event_waiter.waiter;
                waiter.prev = null;
                waiter.next = head;
                waiter.tail = if (head == null) waiter else null;

                // Lazily initialize the Event object to prepare for waiting.
                if (!has_event) {
                    has_event = true;
                    waiter.event.init();
                }

                // Push this waiter to the head of the wait list.
                //
                // Release ordering on success to ensure release() thread 
                // which Acquire loads sees our Waiter/Event writes above.
                if (atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    (state & ~WAITING) | @ptrToInt(waiter),
                    .release,
                    .relaxed,
                )) |updated| {
                    state = updated;
                    continue;
                }

                // Wait for a release()'ing thread to wake us up
                waiter.event.wait(null) catch unreachable;
                
                // Reset all the state in order to spin again
                waiter.event.reset();
                spin_iter = 0;

                // Use `fetchSub` on x86 as it can be done without a `lock cmpxchg` loop.
                // Use `fetchAnd` for others as bitwise ops are generally less expensive than common arithmetic.
                state = switch (builtin.arch) {
                    .i386, .x86_64 => atomic.fetchSub(&self.state, WAKING, .relaxed),
                    else => atomic.fetchAnd(&self.state, ~@as(usize, WAKING), .relaxed),
                };
                state &= ~@as(usize, WAKING);
            }
        }

        /// Release ownership of the Lock, assuming already acquired.
        pub fn release(self: *Lock) void {
            if (use_valgrind) {
                helgrind.annotateHappensBefore(@ptrToInt(self));
            }

            const state = switch (byte_swap) {
                true => blk: {
                    atomic.store(@ptrCast(*u8, &self.state), UNLOCKED, .Release);
                    break :blk atomic.load(&self.state, .Relaxed);
                },
                else => atomic.fetchSub(
                    &self.state,
                    LOCKED,
                    .Release,
                ),
            };

            // NOTE: we could also check if its not waking (or locked for byte_swap)
            // but its slightly better to keep the i-cache hit smaller.
            if (state & WAITING != 0)
                self.releaseSlow();
        }

        fn releaseSlow(self: *Lock) void {
            @setCold(true);

            // Try to grab the WAKING bit, bailing under a few conditions:
            // - bail if theres no waiters to wake
            // - bail if the LOCKED bit is held, the locker will do the wake
            // - bail if the WAKING bit is held, theres already a thread waking.
            //
            // Acquire ordering on success as we'll be deferencing the Waiter from the state 
            // and need to see its writes published by Release above when enqueued.
            //
            // Consume ordering to be precise which provides Acquire guarantees but with the
            // possibility of less synchronization overhead since the memory we're Acquiring
            // is derived from the atomic variable (state) itself.
            var state = atomic.load(&self.state, .Relaxed);
            while (true) {
                if ((state & WAITING == 0) or (state & (LOCKED | WAKING) != 0))
                    return;
                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    state | WAKING,
                    .Consume,
                    .Relaxed,
                ) orelse break;
            }

            state |= WAKING;
            while (true) {
                // Compute the head and the tail of the wait queue
                // so we can dequeue and wake up the tail waiter.
                //
                // - The head is guaranteed to be non-null due to the loop above
                // and due to the fact that the only thread which can zero it is us (WAKING bit).
                //
                // - The tail is queried by following the head Waiter and down its .next chain
                //   until it finds the Waiter with its .tail field set, setting the .prev along the way.
                //
                //   The first waiter enqueued is guaranteed to have its .tail set to itself
                //   and complete the loop as per the code in acquireSlow().
                //
                //   After finding the tail, it is cached at the head node's tail field.
                //   This immediately resolves in future lookups to make the traversal amortized(O(n)) at most.
                const head = @intToPtr(*Waiter, state & WAITING);
                const tail = head.tail orelse blk: {
                    var current = head;
                    while (true) {
                        const next = current.next orelse unreachable;
                        next.prev = current;
                        current = next;
                        if (current.tail) |tail| {
                            head.tail = tail;
                            break :blk tail;
                        }
                    }
                };
                
                // If the LOCKED bit is currently held, 
                // then we should just let the lock holder do the wakeup instead.
                //
                // Release ordering to ensure the head/tail writes we did above are visible to the next waker thread.
                // Acquire/Consume ordering requirement is listed above in grabbing of the WAKING bit.
                if (state & LOCKED != 0) {
                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state & ~@as(usize, WAKING),
                        .Release,
                        .Consume,
                    ) orelse return;
                    continue;
                }

                // If we aren't the last waiter, then just do a normal dequeue
                // by updating the head's tail reference to denote that we're no longer in the queue.
                //
                // Release ordering to ensure that future WAKING threads see the head.tail update.
                if (tail.prev) |new_tail| {
                    head.tail = new_tail;
                    atomic.fence(.Release);

                // If we *are* the last waiter, we need to zero out the Waiter bits from the state in order to dequeue.
                // At this point, we're also not LOCKED so the only thing we need to leave is the WAKING bit which the tail will unset on wake.
                //
                // Release and Acquire/Consume ordering as explained above.
                // TODO: Is release actually necessary here given no threads see our changes on success?
                } else {
                    if (atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        WAKING,
                        .Release,
                        .Consume,
                    )) |updated| {
                        state = updated;
                        continue;
                    }
                }

                tail.event.set();
                return;
            }
        }
    };
}

pub const DebugLock = extern struct {
    mutex: DebugMutex = .{},

    const Self = @This();
    const DebugMutex = @import("./Mutex.zig").DebugMutex;

    pub fn tryAcquire(self: *Self) bool {
        return self.mutex.tryAcquire() != null;
    }

    pub fn acquire(self: *Self) void {
        _ = self.mutex.acquire();
    }

    pub fn release(self: *Self) void {
        (DebugMutex.Held{ .mutex = &self.mutex }).release();
    }
};

test "Lock" {
    const TestLock = std.sync.Lock;

    {
        var lock = TestLock{};
        testing.expect(lock.tryAcquire());
        testing.expect(!lock.tryAcquire());
        lock.release();

        lock.acquire();
        lock.release();
    }

    if (std.io.is_async) return;
    if (std.builtin.single_threaded) return;

    const Contention = struct {
        level: Level = undefined,
        start_event: std.sync.ResetEvent = .{},
        counters: [num_counters]Counter = [_]Counter{Counter{}} ** num_counters,

        const Self = @This();
        const num_counters = 100;
        const Level = enum{ random, high };

        const Counter = struct {
            lock: TestLock = .{},
            remaining: u128 = 10000,

            fn tryDecr(self: *Counter) bool {
                self.lock.acquire();
                defer self.lock.release();

                if (self.remaining == 0)
                    return false;

                self.remaining -= 1;
                return true;
            }
        };

        fn run(self: *Self) void {
            self.start_event.wait();

            switch (self.level) {
                .random => self.runRandomContention(),
                .high => self.runHighContention(),
            }
        }

        fn runHighContention(self: *Self) void {
            const counter = &self.counters[0];
            // counter.remaining *= num_counters;

            while (counter.tryDecr()) {
                atomic.spinLoopHint();
            }
        }

        fn runRandomContention(self: *Self) void {
            var seed: usize = undefined;
            var prng = std.rand.DefaultPrng.init(@ptrToInt(&seed));

            while (true) {
                var did_decr = false;
                var iter = self.counters.len;
                var index = prng.random.int(usize) % iter;

                while (iter > 0) : (iter -= 1) {
                    const counter = &self.counters[index];
                    index = (index + 1) % self.counters.len;
                    did_decr = counter.tryDecr() or did_decr;
                }

                if (!did_decr)
                    break;
            }
        }

        fn execute(self: *Self) !void {
            const allocator = testing.allocator;
            const threads = try allocator.alloc(*std.Thread, 10);
            defer allocator.free(threads);

            for ([_]Level{ .high, .random }) |contention_level| {
                self.level = contention_level;

                self.start_event.reset();
                for (threads) |*t| {
                    t.* = try std.Thread.spawn(self, Self.run);
                }

                self.start_event.set();
                for (threads) |t| {
                    t.wait();
                }
            }
        }
    };

    var contention = Contention{};
    try contention.execute();
}
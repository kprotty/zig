// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../../std.zig");
const atomic = @import("../../atomic.zig");

const builtin = std.builtin;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

/// ParkingLot Lock implementation which uses the given Event abstraction.
pub fn EventLock(
    comptime Event: type,
    comptime Cancellation: type,
) type {
    return extern struct {
        state: usize = UNLOCKED,

        // True if the target supports atomic operations of different sizes on the same address.
        // Ive only ever observed this to be false on obscure platforms like Itanium [1], which Zig doesn't seem to target yet.
        // [1]: (IA64 Vol 3A, Section 8.1.2.2) https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf
        const use_byte_ops = true;

        const UNLOCKED = 0;
        const LOCKED = 1 << 0;
        const WAKING = 1 << (if (use_byte_ops) 8 else 1);
        const WAITING = ~@as(usize, (WAKING << 1) - 1);

        const Self = @This();
        const Waiter = struct {
            prev: ?*Waiter,
            next: ?*Waiter,
            tail: ?*Waiter,
            event: Event align(std.math.max(@alignOf(Event), ~WAITING + 1)),
        };

        /// Try to acquire the Lock, using the passed in state as the assume current value.
        /// Uses Acquire memory ordering on success to see changes release()'d by last lock holder.
        inline fn tryAcquireFast(self: *Self, state: usize) bool {
            // On x86, "lock bts" has a smaller i-cache footprint than the alternative below.
            if (builtin.arch == .i386 or .arch == .x86_64) {
                return atomic.bitSet(
                    &self.state,
                    @ctz(std.math.Log2Int(usize), LOCKED),
                    .Acquire,
                ) == 0;
            }

            // If byte-level atomic operations are supported, try to swap only the lower byte with LOCKED.
            // This is better than the alternative below since it doesn't contend with non-locking CAS' in other functions.
            // It is also made possible by forcing all the non-locking state to be above the LSB byte.
            if (use_byte_ops) {
                return atomic.swap(
                    @ptrCast(*u8, &self.state),
                    LOCKED,
                    .Acquire,
                ) == UNLOCKED;
            }

            // For platforms that don't support any of the fancy tricks above, a normal CAS should work fine.
            return atomic.tryCompareAndSwap(
                &self.state,
                state,
                state | LOCKED,
                .Acquire,
                .Relaxed,
            ) == null;
        }

        pub fn acquire(self: *Self) Held {
            // Fast-path: speculatively try to acquire the lock assuming its unlocked.
            if (!self.tryAcquireFast(UNLOCKED)) {
                self.acquireSlow();
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .lock = self };
        }

        /// Slow-path: acquire the lock by possibly blocking the caller using the Event type.
        fn acquireSlow(self: *Self) void {
            @setCold(true);

            // The waiter's Event object is lazily initialized due to possibly being expensive.
            var waiter: Waiter = undefined;
            var event_initialized = false;
            defer if (event_initialized) {
                waiter.event.deinit();
            };

            var adaptive_spin: usize = 0;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                // Try to acquire the Lock if its unlocked.
                if (state & LOCKED == 0) {
                    if (self.tryAcquireFast(state)) {
                        return;
                    }

                    // If we failed to acquire the lock, yield the processor a little bit.
                    // The goal here is to reduce contention on the state, assuming theres other fast processors.
                    if (Event.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                    } else {
                        atomic.spinLoopHint();
                    }

                    state = atomic.load(&self.state, .Relaxed);
                    continue;
                }

                // Spin on the lock state without thrashing its cache-line by only load()'ing.
                // Only spin if theres no waiters (head == null) as its better to just wait instead.
                // Also don't spin if the Event object told use that we've been spinning too long.
                const head = @intToPtr(?*Waiter, state & WAITING);
                if (head == null and Event.yield(adaptive_spin)) {
                    adaptive_spin +%= 1;
                    state = atomic.load(&self.state, .Relaxed);
                    continue;
                }

                // Prepare the waiter to be added as the new head of the wait queue in the state.
                // The first waiter (head == null) to be added sets its .tail to point to itself.
                // This is further explained in the .tail lookup inside releaseSlow().
                waiter.prev = null;
                waiter.next = head;
                waiter.tail = if (head == null) &waiter else null;
                if (!event_initialized) {
                    waiter.event.init();
                    event_initialized = true;
                }

                // Try to enqueue the waiter onto the lock-state's wait queue.
                // Release barrier to make the waiter writes above visible to the dequeue thread in releaseSlow().
                if (atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    (state & ~WAITING) | @ptrToInt(&waiter),
                    .Release,
                    .Relaxed,
                )) |updated| {
                    state = updated;
                    continue;
                }

                // The waiter is now in the wait queue.
                // Wait for a wakeup from a release() thread.
                waiter.event.wait(null) catch unreachable;

                // Now that we've woken up, reset our state and try to acquire the lock again.
                adaptive_spin = 0;
                waiter.event.reset();
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub const Held = struct {
            lock: *Self,

            pub fn release(self: Held) void {
                self.lock.release();
            }
        };

        fn release(self: *Self) void {
            var state: usize = undefined;
            var should_wake: bool = undefined;

            if (helgrind) |hg| {
                hg.annotateHappensBefore(@ptrToInt(self));
            }

            // Drop ownership of the lock by unsetting the LOCKED bit.
            // If byte-ops are available, we can use an atomic store instead of an rmw op
            // since the entire LSB byte is reserved for the LOCKED bit.
            //
            // Uses a Release barrier to synchronize with the Acquire in tryAcquireFast()
            // in order to publish memory updates to the next lock-holding thread.
            if (use_byte_ops) {
                atomic.store(@ptrCast(*u8, &self.state), UNLOCKED, .Release);
                state = atomic.load(&self.state, .Relaxed);
                should_wake = state & (LOCKED | WAKING) == 0;
            } else {
                state = atomic.fetchAnd(&self.state, ~@as(usize, LOCKED), .Release);
                should_wake = state & WAKING == 0;
            }

            // Take the slow path to wake up a waiter only when necessary
            const has_waiters = state & WAITING != 0;
            if (has_waiters and should_wake) {
                self.releaseSlow();
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);

            // In order to dequeue and wake up a Waiter, we must acquire the WAKING bit.
            // At this point we have release ownership of the Lock so other threads can acquire it while we wake.
            // If theres no waiters to wake up or if theres already a thread doing the wake-up, we give up.
            // We also give up if theres a Lock holder since we can leave it to them to do the wake-up instead.
            var state = atomic.load(&self.state, .Relaxed);
            while (true) {
                if ((state & WAITING == 0) or (state & (LOCKED | WAKING) != 0)) {
                    return;
                }

                // Acquire barrier on success which is needed to make visible the waiter.field
                // writes that were Release'd by the waiter when it enqueued itself.
                state = atomic.tryCompareAndSwap(
                    &self.state,
                    state,
                    state | WAKING,
                    .Acquire,
                    .Relaxed,
                ) orelse {
                    state |= WAKING;
                    break;
                };
            }

            while (true) {
                // Get the head of the wait queue from the state.
                // This is bound to be a valid pointer as it was confirmed above
                // when acquiring the WAKING bit and we're the only thread that can now dequeue.
                const head = @intToPtr(*Waiter, state & WAITING);

                // Search for the tail of the wait queue by starting from the head and following .next fields.
                // Along the way, link up the .prev fields in order to make the queue a proper doubly-linked-list.
                //
                // The loop is bound to end as the first waiter in the queue must have its .tail field set to itself.
                // Once we find the tail, we can cache it at the head waiter to amortize the cost of future lookups.
                //
                // Effectively, we only scan through each Waiter once after it has been enqueued.
                // So its still O(n) but n = amount of new waiters enqueued since the last wake-up.
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

                // If the Lock is currently owned, we should leave the wake-up to that thread instead.
                // For that, we unset the WAKING bit so that thread's eventual releaseSlow() can do the wake up.
                //
                // On success, we need a Release barrier to ensure the next WAKING thread sees the writes when searching for tail we did above.
                // On failure, we need an Acquire barrier to see the writes to any new Waiters that enqueued themselves as the head.
                if (state & LOCKED != 0) {
                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state & ~@as(usize, WAKING),
                        .AcqRel, // TODO: could be just .Release ?
                        .Acquire,
                    ) orelse return;
                    continue;
                }

                // If the tail isn't the last waiter in the queue,
                // then we dequeue it normally by logically detaching it from the doubly linked list.
                //
                // After we dequeued the tail, we need to unset the WAKING bit to allow another thread to wake-up.
                // This is done with a Release barrier to ensure the next WAKING thread sees the updated head.tail.
                if (tail.prev) |new_tail| {
                    head.tail = new_tail;
                    _ = atomic.fetchAnd(&self.state, ~@as(usize, WAKING), .Release);
                    tail.event.set();
                    return;
                }

                // If this is the last waiter in the queue, then we need to zero out the queue pointer in the state.
                // While we're zeroing it out, we also unset the WAKING bit so that we can wake up the tail.
                while (true) {
                    state = atomic.tryCompareAndSwap(
                        &self.state,
                        state,
                        state & LOCKED,
                        .AcqRel,
                        .Relaxed,
                    ) orelse {
                        tail.event.set();
                        return;
                    };

                    // If a new waiter added itself while we were trying to zero out the wait queue state
                    // then we need to retry the dequeue since the new waiter now references the tail.
                    // Acquire barrier here in order to ensure we see the waiter writes when we loop back above.
                    if (@intToPtr(?*Waiter, state & WAITING) != tail) {
                        atomic.fence(.Acquire);
                        break;
                    }
                }
            }
        }
    };
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const atomic = @import("./atomic.zig");

pub fn ParkingLot(comptime config: anytype) type {
    return struct {
        fn hasConfig(comptime field: []const u8) bool {
            return @hasDecl(@TypeOf(config), field);
        }

        pub const Event: type = switch (hasConfig("Event")) {
            true => config.Event,
            else => DefaultEvent,
        };

        pub const Lock: type = switch (hasConfig("Lock")) {
            true => config.Lock,
            else => DefeaultLock(Event),
        };

        pub const Timestamp: type = switch (hasConfig("Timestamp")) {
            true => config.Timestamp,
            else => DefaultTimestamp,
        };

        pub const bucket_count: usize = switch (hasConfig("bucket_count")) {
            true => config.bucket_count,
            else => DEFAULT_BUCKET_COUNT,
        };

        pub const Token = usize;

        pub const FilterOp = union(enum) {
            Stop,
            Skip,
            Unpark: Token,
        };

        pub const RequeueOp = enum {
            UnparkOne,
            RequeueOne,
            UnparkOneRequeueRest,
            RequeueAll,
        };

        pub const Unparked = struct {
            token: ?Token,
            has_more: bool,
            timestamp_expired: bool,
        };

        pub fn park(
            address: usize,
            cancellation: ?Event.Cancellation,
            callback: anytype, 
        ) error{Invalidated, Cancelled}!Token {
            var node: WaitNode = undefined;
            const bucket = WaitBucket.from(address);

            {
                var held: Lock.Held = undefined;
                bucket.lock.acquire(&held);
                defer bucket.lock.release(&held);

                _ = atomic.fetchAdd(&bucket.waiters, 1, .SeqCst);

                const park_token: ?Token = callback.onValidate();
                node.token = park_token orelse {
                    _ = atomic.fetchSub(&bucket.waiters, 1, .SeqCst);
                    return error.Invalidated;
                };

                node.event.init();
                bucket.queue(address).insert(&node);
                callback.onBeforeWait();
            }

            var cancelled = false;
            node.event.wait(cancellation) catch {
                cancelled = true;
            };

            if (cancelled) {
                {
                    bucket.lock.acquire(&held);
                    defer bucket.lock.release(&held);

                    cancelled = bucket.contains(&node);
                    if (cancelled) {
                        _ = atomic.fetchSub(&bucket.waiters, 1, .SeqCst);
                        var queue = bucket.queue(address);
                        queue.remove(&node);
                        callback.onCancel(Unparked{
                            .token = node.token,
                            .has_more = !queue.isEmpty(),
                            .timestamp_expired = false,
                        });
                    }
                }

                if (!cancelled) {
                    node.event.wait(null) catch unreachable;
                }
            }

            node.event.deinit();
            return if (cancelled) error.Cancelled else node.token;
        }

        pub fn unparkRequeue(
            address: usize,
            requeue: usize,
            callback: anytype,
        ) void {
            var unparked = List{};
            defer while (unparked.pop()) |node| {
                node.event.set();
            };

            const bucket = WaitBucket.from(address);
            if (atomic.load(&bucket.waiters, .SeqCst) == 0) {
                return;
            }

            var held: Lock.Held = undefined;
            bucket.lock.acquire(&held);
            defer bucket.lock.release(&held);

            var requeue_held: Lock.Held = undefined;
            const requeue_bucket = WaitBucket.from(requeue_address);
            if (bucket != requeue_bucket) {
                requeue_bucket.lock.acquire(&requeue_held);
            }
            defer if (bucket != requeue_bucket) {
                requeue_bucket.lock.release(&requeue_held);
            };

            const requeue_op: RequeueOp = callback.onRequeue();
            var max_unpark = switch (requeue_op) {
                .UnparkOne, .UnparkOneRequeueRest => 1,
                .RequeueOne, .RequeueAll => 0,
            };
            var max_requeue = switch (requeue_op) {
                .UnparkOne => 0,
                .RequeueOne => 1,
                .RequeueAll, .UnparkOneRequeueRest => std.math.maxInt(usize),
            };
            
            var queue = bucket.queue(address);
            while (max_unpark > 0) : (max_unpark -= 1) {
                const node = queue.pop() orelse break;
                unparked.push(node);
            }

            var requeued: usize = 0;
            if (max_requeue > 0) {
                if (queue.pop()) |starting_node| {
                    var requeue_node = starting_node;
                    var requeue_queue = requeue_bucket.queue(requeue_address);
                    while (max_requeue > 0) : (max_requeue -= 1) {
                        const node = requeue_node orelse break;
                        requeue_queue.push(node);
                        requeued += 1;
                        requeue_node = queue.pop();
                    }
                }
            }

            callback.onBeforeWake()

            if (bucket != requeue_bucket and requeued > 0) {
                _ = atomic.fetchSub(&bucket.waiters, unparked.len + requeued, .SeqCst);
                _ = atomic.fetchAdd(&requeue_bucket.waiters, requeued, .SeqCst);
            } else if (unparked.len > 0) {
                _ = atomic.fetchSub(&bucket.waiters, unparked.len, .SeqCst);
            }
        }

        pub fn unparkFilter(
            address: usize,
            callback: anytype,
        ) void {
            @compileError("TODO");
        }

        pub fn unparkOne(
            address: usize,
            callback: anytype,
        ) void {
            const Callback = @TypeOf(callback);
            const FilterCallback = struct {
                callback: Callback,
                called_unparked: bool = false,
                
                pub fn onFilter(self: *@This(), waiter: Waiter) FilterOp {
                    if (self.called_unparked) {
                        return .Stop;
                    }

                    const unpark_token: Token = self.callback.onUnparked(Unparked{
                        .token = waiter.getToken(),
                        .has_more = waiter.hasMore(),
                        .timestamp_expired = waiter.didTimestampExpire(),
                    });

                    self.called_unparked = true;
                    return .{ .Unpark = unpark_token };
                }

                pub fn onBeforeWake(self: @This()) void {
                    if (self.called_unparked) {
                        const unpark_token: Token = self.callback.onUnparked(Unparked{
                            .token = null,
                            .has_more = false,
                            .timestamp_expired = false,
                        });
                    }
                }
            };
            
            var filter_callback = FilterCallback{ .callback = callback };
            unparkFilter(address, &filter_callback);
        }

        pub fn unparkAll(
            address: usize,
            token: Token,
        ) void {
            const FilterCallback = struct {
                unpark_token: Token,

                pub fn onFilter(self: @This(), waiter: Waiter) FilterOp {
                    return .{ .Unpark = self.unpark_token };
                }

                pub fn onBeforeWake(self: @This()) void {
                    // no-op
                }
            };

            const filter_callback = FilterCallback{ .unpark_token = token };
            unparkFilter(address, filter_callback);
        }
    };
}

pub const DEFAULT_BUCKET_COUNT: usize = std.meta.bitCount(usize) << 2;

pub const DefaultTimestamp = struct {
    const Self = @This();

    pub fn now() Self {
        return .{};
    }

    pub fn expires(self: Self, timestamp: Self) bool {
        return false;
    }

    pub fn update(self: *Self, timestamp: Self, rng: u64) {
        // no-op
    }
};

pub const DefaultEvent = struct {
    is_set: bool,

    const Self = @This();

    pub fn init(self: *Self) void {
        @compileError("TODO");
    }

    pub fn deinit(self: *Self) void {
        @compileError("TODO");
    }

    pub fn reset(self: *Self) void {
        @compileError("TODO");
    }

    pub fn set(self: *Self) void {
        @compileError("TODO");
    }

    pub const Cancellation = void;

    pub fn wait(self: *Self, cancellation: ?Cancellation) error{Cancelled}!void {
        @compileError("TODO");
    }
};

pub fn DefaultLock(comptime Event: type) type {
    return extern struct {
        state: usize = UNLOCKED,

        // True when the target is in the class of x86 chips, false otherwise.
        // This is used to select certain cpu instructions for the occasion.
        const is_x86 = std.builtin.arch == .i386 or .arch == .x86_64;
        
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

        pub const Held = void;        

        /// Try to acquire the Lock, using the passed in state as the assume current value.
        /// Uses Acquire memory ordering on success to see changes release()'d by last lock holder.
        inline fn tryAcquireFast(self: *Self, state: usize) bool {
            // On x86, "lock bts" has a smaller i-cache footprint than the alternative below.
            if (std.builtin.arch == .i386 or .arch == .x86_64) {
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

        pub fn acquire(self: *Self, held: *Held) void {
            // Fast-path: speculatively try to acquire the lock assuming its unlocked.
            if (!self.tryAcquireFast(UNLOCKED)) {
                self.acquireSlow();
            }
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
                waiter.event.wait();

                // Now that we've woken up, reset our state and try to acquire the lock again.
                adaptive_spin = 0;
                waiter.event.reset();
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub fn release(self: *Self, held: *Held) void {
            var state: usize = undefined;
            var slow_mask: usize = undefined;
            
            if (use_byte_ops) {
                atomic.store(@ptrCast(*u8, &self.state), UNLOCKED, .Release);
                state = atomic.load(&self.state, .Relaxed);
                slow_mask = LOCKED | WAKING;
            } else {
                state = atomic.fetchSub(&self.state, LOCKED, .Release);
                slow_mask = WAKING;
            }

            if ((state & WAITING != 0) and (state & slow_mask != 0)) {
                self.releaseSlow();
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);

            @compileError("TODO");
        }
    };
}

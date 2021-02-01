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

        const Event: type = switch (hasConfig("Event")) {
            true => config.Event,
            else => DefaultEvent,
        };

        const Lock: type = switch (hasConfig("Lock")) {
            true => config.Lock,
            else => DefeaultLock(Event),
        };

        const Timestamp: type = switch (hasConfig("Timestamp")) {
            true => config.Timestamp,
            else => DefaultTimestamp,
        };

        const bucket_count: usize = switch (hasConfig("bucket_count")) {
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

        const UNLOCKED: usize = 0;
        const LOCKED: usize = 1 << 0;
        const WAKING: usize = 1 << 1;
        const WAITING: usize = ~(LOCKED | WAKING);

        const Self = @This();
        const Waiter = struct {
            prev: ?*Waiter,
            next: ?*Waiter,
            tail: ?*Waiter,
            event: Event align(std.math.max(@alignOf(Event), ~WAITING + 1)),
        };

        pub const Held = void;

        pub fn acquire(self: *Self, held: *Held) void {
            @compileError("TODO");
        }

        pub fn release(self: *Self, held: *Held) void {
            @compileError("TODO");
        }
    };
}

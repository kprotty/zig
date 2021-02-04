// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const atomic = @import("./atomic.zig");

const builtin = std.builtin;
const assert = std.debug.assert;

pub fn ParkingLot(comptime Config: type) type {
    return struct {
        fn isConfigOptional(comptime field: []const u8) bool {
            return std.meta.activeTag(@typeInfo(@field(Config, field))) == .Optional;
        }

        fn hasConfig(comptime field: []const u8) bool {
            if (!@hasDecl(Config, field)) {
                return false;
            } else if (isConfigOptional(field) and @field(Config, field) == null) {
                return false;
            } else {
                return true;
            }
        }

        fn getConfig(comptime field: []const u8) getConfigType(field) {
            const value = @field(Config, field);
            if (isConfigOptional(field)) {
                return value orelse unreachable;
            } else {
                return value;
            }
        }

        fn getConfigType(comptime field: []const u8) type {
            const FieldType = @TypeOf(@field(Config, field));
            return switch (@typeInfo(FieldType)) {
                .Optional => |info| info.child,
                else => FieldType,
            };
        }

        // TODO: Document
        pub const Event = WaitEvent;
        const WaitEvent: type = switch (hasConfig("Event")) {
            true => getConfig("Event"),
            else => switch (hasConfig("Futex")) {
                true => DefaultFutexEvent(getConfig("Futex")),
                else => @compileError("ParkingLot requires either a Futex or an Event implementation"),
            },
        };

        // TODO: Document
        pub const Lock = WaitLock;
        const WaitLock: type = switch (hasConfig("Lock")) {
            true => getConfig("Lock"),
            else => switch (hasConfig("Futex")) {
                true => DefaultFutexLock(getConfig("Futex")),
                else => DefaultLock(Event),
            },
        };

        // TODO: Document
        pub const Futex: type = switch (hasConfig("Futex")) {
            true => getConfig("Futex"),
            else => DefaultFutex(@This()),
        };

        // TODO: Document
        pub const bucket_count = wait_bucket_count;
        const wait_bucket_count: usize = switch (hasConfig("bucket_count")) {
            true => getConfig("bucket_count"),
            else => std.meta.bitCount(usize) << 2,
        };

        // TODO: Document
        pub const Timestamp = FairTimestamp;
        const FairTimestamp: type = switch (hasConfig("Timestamp")) {
            true => getConfig("Timestamp"),
            else => struct {
                const Self = @This();

                pub fn now() Self {
                    return Self{};
                }

                pub fn expires(self: *Self, current_now: Self) bool {
                    return false;
                }

                pub fn update(self: *Self, current_now: Self, rng: u64) void {
                    // no-op
                }
            },
        };

        // TODO: Document
        pub const Token = usize;

        // TODO: Document
        pub const Waiter = struct {
            _token: Token,
            _has_more: bool,
            _bucket: *WaitBucket,

            // TODO: Document
            pub fn getToken(self: Waiter) Token {
                return self._token;
            }

            // TODO: Document
            pub fn hasMore(self: Waiter) bool {
                return self._has_more;
            }

            // TODO: Document
            pub fn didTimestampExpire(self: Waiter) bool {
                return self._bucket.didTimestampExpire();
            }
        };

        // TODO: Document
        pub const Filtered = union(enum) {
            Stop,
            Skip,
            Unpark: Token,
        };

        // TODO: Document
        pub const Requeued = struct {
            unpark: usize = 0,
            requeue: usize = 0,
        };

        // TODO: Document
        pub const Unparked = struct {
            token: ?Token = null,
            has_more: bool = false,
            timestamp_expired: bool = false,
        };

        // TODO: Document
        pub fn park(
            address: usize,
            cancellation: ?*WaitEvent.Cancellation,
            callback: anytype,
        ) error{ Invalidated, Cancelled }!Token {
            var node: WaitNode = undefined;

            {
                // Then grab the WaitBucket lock for this address in order to
                // prepare for an enqueue & synchronize with unpark()
                var held: WaitLock.Held = undefined;
                const bucket = WaitBucket.from(address);
                bucket.acquire(&held);
                defer bucket.release(&held);

                // Update the wait count for the bucket before calling the onValidate() function below.
                // If done after, then an unpark() thread could see waiters = 0,
                // after we validate the wait but before enqueue to wait,
                // causing this waiter to miss an unpark() notification.
                _ = atomic.fetchAdd(&bucket.waiters, 1, .SeqCst);

                // Call the `onValidate()` callback which double checks that the caller should actually wait.
                // If it returns null, then it should not wait so it reverts any changes made so far in preparation.
                // If it returns a Token, the Token is used for the duration of the wait to tag the Waiter for the unpark() threads.
                node.token = callback.onValidate() orelse {
                    _ = atomic.fetchSub(&bucket.waiters, 1, .SeqCst);
                    return error.Invalidated;
                };

                // Prepare our WaitNode to wait by enqueuing it and initializing any extra state.
                var queue = bucket.queue(address);
                const had_more = !queue.isEmpty();
                queue.push(&node);
                node.event.init();
            }

            // Now that our WaitNode is enqueued, wait on its event.
            // `onBeforeWait()` is called just before to do any pre-park work.
            var cancelled = false;
            callback.onBeforeWait();
            node.event.wait(cancellation) catch {
                cancelled = true;
            };

            // If our wait was cancelled, we need to remove our Wait
            if (cancelled) {
                {
                    var addr: usize = undefined;
                    var held: WaitLock.Held = undefined;
                    var bucket: *WaitBucket = undefined;
                    defer bucket.release(&held);

                    // Find the WaitBucket for our WaitNode and acquire its lock.
                    // We keep retrying if our node address changes due to a requeue.
                    //
                    // Our node address can only change while the bucket is locked so
                    // the loop will eventually terminate as long as we dont keep losing
                    // the lock race and keep getting requeued.
                    while (true) {
                        addr = atomic.load(&node.address, .Relaxed);
                        bucket = WaitBucket.from(addr);
                        bucket.acquire(&held);
                        if (node.address == addr) {
                            break;
                        } else {
                            bucket.release(&held);
                        }
                    }

                    // Once we find our WaitBucket, try to remove our WaitNode from its WaitQueue.
                    // If we succeed in doing so, invoke the `onCancel()` callback with the state of the WaitQueue.
                    //
                    // This can fail if another thread manages to dequeue us before we get here.
                    // If so, we need to make sure that thread no longer has a reference to our WaitNode before we return.
                    cancelled = WaitNode.isEnqueued(&node);
                    if (cancelled) {
                        _ = atomic.fetchSub(&bucket.waiters, 1, .SeqCst);
                        var queue = bucket.queue(addr);
                        queue.remove(&node);

                        callback.onCancel(Unparked{
                            .token = node.token,
                            .has_more = !queue.isEmpty(),
                            .timestamp_expired = false,
                        });
                    }
                }

                // If we failed to cancel and remove our WaitNode from the WaitQueue,
                // it means that another thread dequeued us and is in the process of waking us up.
                //
                // Wait for that thread to wake up our WaitNode by setting its event
                // to make sure that it no longer has any reference to our WaitNode before we return.
                if (!cancelled) {
                    node.event.wait(null) catch unreachable;
                }
            }

            node.event.deinit();
            return if (cancelled) error.Cancelled else node.token;
        }

        /// Unparks/wakes-up all waiters waiting on the wait queue for `address` using the given `Token`.
        pub fn unparkAll(
            address: usize,
            token: Token,
        ) void {
            const FilterCallback = struct {
                unpark_token: Token,

                pub fn onFilter(self: @This(), waiter: Waiter) Filtered {
                    return .{ .Unpark = self.unpark_token };
                }

                pub fn onBeforeWake(self: @This()) void {
                    // no-op
                }
            };

            const filter_callback = FilterCallback{ .unpark_token = token };
            unparkFilter(address, filter_callback);
        }

        /// Unparks/wakes-up one waiter waiting on the wait queue for `address`.
        ///
        /// While the lock for the wait queue on `address` is held, `callback.onUnpark` is called with an instance of `Unparked`.
        /// The result of the onUnpark() function is a `Token` which is used to unpark/wake-up the corresponding waiter if any.
        /// In regards to the values of `Unparked`:
        ///     - token: ?Token => null if no waiter was found, otherwise its the `Token` of a parked waiter.
        ///     - has_more: bool => true if theres more waiters in the wait queue after the dequeue of this waiter if any.
        ///     - timestamp_expired: bool => true if the internal timestamp for the WaitQueue ticked
        pub fn unparkOne(
            address: usize,
            callback: anytype,
        ) void {
            const Callback = @TypeOf(callback);
            const FilterCallback = struct {
                callback: Callback,
                called_unparked: bool = false,

                pub fn onFilter(self: *@This(), waiter: Waiter) Filtered {
                    if (self.called_unparked) {
                        return .Stop;
                    }

                    const unpark_token: Token = self.callback.onUnpark(Unparked{
                        .token = waiter.getToken(),
                        .has_more = waiter.hasMore(),
                        .timestamp_expired = waiter.didTimestampExpire(),
                    });

                    self.called_unparked = true;
                    return .{ .Unpark = unpark_token };
                }

                pub fn onBeforeWake(self: @This()) void {
                    if (self.called_unparked) {
                        _ = self.callback.onUnpark(Unparked{});
                    }
                }
            };

            var filter_callback = FilterCallback{ .callback = callback };
            unparkFilter(address, &filter_callback);
        }

        /// Iterate the wait queue for `address` and selectively unpark/wake-up specific waiters.
        ///
        /// For each waiter in the wait queue while holding its lock, it creates a `Waiter` instance
        /// which can be used to get various information about the WaitQueue as well as the waiter's Token.
        /// This `Waiter` instance is used to call `callback.onFilter` which returns a `FilterOp` which decides whether to:
        ///     - FilterOp.Stop: stop scaning the wait queue and finish up any other operations.
        ///     - FilterOp.Skip: leave the waiter represented by the `Waiter` instance in the wait queue.
        ///     - FilterOp.Unpark(Token): dequeue and eventually unpark/wakeup the waiter represented by the `Waiter` instance.
        ///
        /// Once the scanning of the wait queue is completed or preempted early via FilterOp.Stop,
        /// `callback.onBeforeWake()` is called while holding the wait queue lock to run anything post-filters.
        pub fn unparkFilter(
            address: usize,
            callback: anytype,
        ) void {
            // Set the event for all the WaitNodes that we unpark.
            // This is done after any WaitBucket locks are dropped.
            var unparked = WaitList{};
            defer while (unparked.pop()) |node| {
                node.event.set();
            };

            // Find the bucket for this address and bail if it has no waiters.
            const bucket = WaitBucket.from(address);
            if (atomic.load(&bucket.waiters, .SeqCst) == 0) {
                return;
            }

            // If waiters are discovered, grab the bucket lock in order to dequeue and wake them.
            var held: WaitLock.Held = undefined;
            bucket.acquire(&held);
            defer bucket.release(&held);

            // Iterate the WaitNodes on this address' WaitQueue and apply the filter operations.
            var queue = bucket.queue(address);
            var iter = queue.iter();
            while (iter.next()) |node| {
                const filter_op: Filtered = callback.onFilter(Waiter{
                    ._token = node.token,
                    ._has_more = !iter.isEmpty(),
                    ._bucket = bucket,
                });

                switch (filter_op) {
                    .Stop => break,
                    .Skip => continue,
                    .Unpark => |unpark_token| {
                        node.token = unpark_token;
                        unparked.push(node);
                    },
                }
            }

            // If any we're unparked, update the waiter count to reflect this.
            if (unparked.len > 0) {
                _ = atomic.fetchSub(&bucket.waiters, unparked.len, .SeqCst);
            }

            // Before we wake up the waiters,
            // call the `onBeforeWake()` callback with the WaitBucket locked.
            callback.onBeforeWake();
        }

        /// Unpark waiters waiting on `address` and move some of the others to wait on `requeue_address`.
        ///
        /// Once the locks for the wait queues of both `address` and `requeue_address` are held, `callback.onRequeue()` is called.
        /// This returns a `?Requeued` instance where null implies that the entire operation should be aborted.
        /// If not aborted:
        ///     - `Requeued.unpark` represents the maximum amount of waiters to unpark from `address` to `requeue_address`
        ///     - `Requeued.requeue` represents the maximum amount of waiters to move waiting on `address` to `requeue_address`.
        ///
        /// Once all the desired waiters are unparked/requeued, `callback.onBeforeWake` is called with both wait queue locks held.
        /// It is given a `Requeued` instance where the `.unpark` and `.requeue` fields represent the amount of waiters that were actually moved around.
        pub fn unparkRequeue(
            address: usize,
            requeue_address: usize,
            callback: anytype,
        ) void {
            // Set the event for all the WaitNodes that we unpark.
            // This is done after any WaitBucket locks are dropped.
            var unparked = WaitList{};
            defer while (unparked.pop()) |node| {
                node.event.set();
            };

            // Find the bucket for the address and bail if there's nothing to unpark/requeue.
            const bucket = WaitBucket.from(address);
            if (atomic.load(&bucket.waiters, .SeqCst) == 0) {
                return;
            }

            // Acquire the bucket lock for the main address.
            var held: WaitLock.Held = undefined;
            bucket.acquire(&held);
            defer bucket.release(&held);

            // Find the bucket for the requeue address and acquire its lock.
            // If the address and requeue_address map to the same bucket,
            // we don't acquire its lock as its the same above and would be UB/deadlock.
            var requeue_held: WaitLock.Held = undefined;
            const requeue_bucket = WaitBucket.from(requeue_address);
            if (bucket != requeue_bucket) {
                requeue_bucket.acquire(&requeue_held);
            }
            defer if (bucket != requeue_bucket) {
                requeue_bucket.release(&requeue_held);
            };

            // With both locks held, run the requeue callback
            // and see how many WaitNodes its requested to unpark and requeue.
            // If `onRequeue()` returns null, then bail out of trying to requeue anything
            const requeue_op: Requeued = callback.onRequeue() orelse return;
            var max_requeue = requeue_op.requeue;
            var max_unpark = requeue_op.unpark;

            // Push the amount of unparked WaitNodes into the unparked WaitList.
            var queue = bucket.queue(address);
            while (max_unpark > 0) : (max_unpark -= 1) {
                const node = queue.pop() orelse break;
                unparked.push(node);
            }

            // Push remaining WaitNodes from the queue into the requeue_queue.
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

            // Update the waiter counts for the buckets are moving WaitNodes around.
            // If the address and requeue_address point to the same bucket,
            // we only need to subtract those which were unparked as the requeued are still waiting.
            if (bucket != requeue_bucket and requeued > 0) {
                _ = atomic.fetchSub(&bucket.waiters, unparked.len + requeued, .SeqCst);
                _ = atomic.fetchAdd(&requeue_bucket.waiters, requeued, .SeqCst);
            } else if (unparked.len > 0) {
                _ = atomic.fetchSub(&bucket.waiters, unparked.len, .SeqCst);
            }

            // After performing the unpark/requeued,
            // invoke the onBeforeWake() while the locks are held
            // passing in how many WaitNodes were actually unparked and requeued.
            callback.onBeforeWake(Requeued{
                .unpark = unparked.len,
                .requeue = requeued,
            });
        }

        const WaitNode = struct {
            address: usize,
            prev: ?*WaitNode,
            next: ?*WaitNode,
            tail: *WaitNode,
            ticket: usize,
            parent: ?*WaitNode,
            children: [2]?*WaitNode,
            xorshift: u16,
            event: WaitEvent,
        };

        const WaitList = struct {
            head: ?*WaitNode = null,
            tail: ?*WaitNode = null,
            len: usize = 0,

            pub fn push(self: *WaitList, node: *WaitNode) void {
                if (self.head == null) self.head = node;
                if (self.tail) |tail| tail.next = node;
                self.tail = node;
                self.len += 1;
                node.next = null;
            }

            pub fn pop(self: *WaitList) ?*WaitNode {
                const node = self.head orelse return null;
                if (node.next == null) self.tail = null;
                self.head = node.next;
                self.len -= 1;
                return node;
            }
        };

        const WaitQueue = struct {
            bucket: *Bucket,
            address: usize,
            parent: ?*WaitNode,
            head: ?*WaitNode,

            pub fn iter(self: *WaitQueue) Iter {
                return Iter{ .node = self.head };
            }

            const Iter = struct {
                node: ?*WaitNode,

                pub fn isEmpty(self: Iter) bool {
                    return self.node == null;
                }

                pub fn next(self: *Iter) ?*WaitNode {
                    const node = self.node orelse return null;
                    self.node = node.next;
                    return node;
                }
            };

            pub fn isEmpty(self: *WaitQueue) bool {
                return self.head == null;
            }

            pub fn isEnqueued(node: *WaitNode) bool {
                return node.ticket != 0;
            }

            pub fn push(self: *WaitQueue, node: *WaitNode) void {
                // generic parts that the WaitNode will have set when inserted
                node.next = null;
                atomic.store(&node.address, self.address, .Relaxed);

                // If theres already a list going on, append to the end of it
                if (self.head) |head| {
                    node.ticket = 1;
                    node.prev = head.tail;
                    head.tail.next = node;
                    head.tail = node;
                    return;
                }

                // If not, we need to create a new tree node.
                // The new node gets a random (non-zero) ticket for rebalancing.
                node.prev = null;
                node.tail = node;
                node.parent = self.parent;
                node.children = [_]?*WaitNode{ null, null };
                node.ticket = self.bucket.genPrng(u16) | 1;

                // Insert the node into the tree and re-balance it by ticket.
                self.head = node;
                self.updateParent(node, node);
                while (node.parent) |parent| {
                    if (parent.ticket <= node.ticket) break;
                    self.rotate(parent, parent.children[0] != node);
                }
            }

            pub fn pop(self: *WaitQueue) ?*WaitNode {
                const node = self.head orelse return null;
                self.remove(node);
                return node;
            }

            pub fn remove(self: *WaitQueue, node: *WaitNode) void {
                // Make sure the node is queued when removing.
                // After we remove it, mark it as such.
                assert(isEnqueued(node));
                defer node.ticket = 0;

                if (node.prev) |prev| prev.next = node.next;
                if (node.next) |next| next.prev = node.prev;

                const head = self.head orelse unreachable;
                if (node != head) {
                    if (node == head.tail) head.tail = node.prev.?;
                    return;
                }

                // If we're the head and theres more nodes, we need to update the head.
                // If we're the head and we're the last node, we need to remove ourselves from the tree.
                if (node.next) |new_head| {
                    new_head.ticket = head.ticket;
                    new_head.parent = head.parent;
                    new_head.children = head.children;
                    for (head.children) |child_ptr| {
                        const child = child_ptr orelse continue;
                        child.parent = new_head;
                    }
                } else {
                    // Rotate ourselves down the tree for removal.
                    while ((head.children[0] orelse head.children[1]) != null) {
                        self.rotate(head, is_left: {
                            const right = head.children[1] orelse break :is_left false;
                            const left = head.children[0] orelse break :is_left true;
                            break :is_left (left.ticket >= right.ticket);
                        });
                    }
                }

                self.head = node.next;
                self.updateParent(node, node.next);
            }

            /// Update the parent of the `node` to point to `new_node`.
            /// `new_node` may alias with `node` (e.g. for insertion).
            fn updateParent(self: *WaitQueue, node: *WaitNode, new_node: ?*WaitNode) void {
                if (node.parent) |parent| {
                    const parent_addr = parent.address;
                    parent.children[@boolToInt(parent_addr > self.address)] = new_node;
                } else {
                    self.bucket.setRoot(new_node);
                }
            }

            /// Rotate the given node in the tree either left or right depending on `left_rotate`.
            fn rotate(self: *WaitQueue, node: *WaitNode, left_rotate: bool) void {
                const swap_with = node.children[@boolToInt(left_rotate)] orelse unreachable;
                const child = swap_with.children[@boolToInt(!left_rotate)];
                const parent = node.parent;

                swap_with.children[@boolToInt(!left_rotate)] = node;
                node.parent = swap_with;
                node.children[@boolToInt(left_rotate)] = child;
                if (child) |child_node| {
                    child_node.parent = node;
                }

                swap_with.parent = parent;
                if (parent) |parent_node| {
                    if (parent_node.children[0] == node) {
                        parent_node.children[0] = swap_with;
                    } else if (parent_node.children[1] == node) {
                        parent_node.children[1] = swap_with;
                    } else {
                        unreachable;
                    }
                } else {
                    self.bucket.setRoot(swap_with);
                }
            }
        };

        /// A WaitBucket is a synchronized collection of WaitQueues.
        /// Each address maps to a given WaitBucket where it can enqueue itself to Wait.
        const WaitBucket = struct {
            lock: WaitLock = WaitLock{},
            waiters: usize = 0,
            root: usize = 0,
            timestamp: FairTimestamp = FairTimestamp{},

            const IS_ROOT_PRNG: usize = 0b01;
            const IS_BUCKET_LOCKED: usize = 0b10;
            const ROOT_NODE_MASK = ~@as(usize, IS_ROOT_PRNG | IS_BUCKET_LOCKED);
            const PRNG_SHIFT = @popCount(std.math.Log2Int(usize), ~ROOT_NODE_MASK);

            var array = [_]WaitBucket{WaitBucket{}} ** std.math.max(1, wait_bucket_count);

            /// Hash an address into a WaitBucket reference.
            pub fn from(address: usize) *WaitBucket {
                return &array[address % array.len];
            }

            /// Acquire ownership of the WaitBucket.
            /// This provides the ability to lookup the WaitQueue for an address and operate on it.
            pub fn acquire(self: *WaitBucket, held: *WaitLock.Held) void {
                held.* = self.lock.acquire();
                assert(self.root & IS_BUCKET_LOCKED == 0);
                self.root |= IS_BUCKET_LOCKED;
            }

            /// Release ownership of the WaitBucket after having previously acquired it.
            /// This relenquishes the safety to lookup WaitQueues on this WaitBucket or operate on existing ones.
            pub fn release(self: *WaitBucket, held: *WaitLock.Held) void {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                self.root &= ~IS_BUCKET_LOCKED;
                held.release();
            }

            /// Lookup the WaitQueue in the WaitBucket for a given address.
            pub fn queue(self: *WaitBucket, address: usize) WaitQueue {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                var parent: ?*WaitNode = null;
                var head: ?*WaitNode = self.getRoot();

                while (true) {
                    const node = head orelse break;
                    if (node.address == address) {
                        break;
                    } else {
                        parent = node;
                        head = node.children[@boolToInt(node_address > address)];
                    }
                }

                return WaitQueue{
                    .bucket = self,
                    .address = address,
                    .parent = parent,
                    .head = head,
                };
            }

            fn getRoot(self: *WaitBucket) ?*WaitNode {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                if (self.root & IS_ROOT_PRNG != 0) {
                    return null;
                } else {
                    return @intToPtr(?*WaitNode, self.root & ROOT_NODE_MASK);
                }
            }

            fn setRoot(self: *WaitBucket, new_root: ?*WaitNode) void {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                const prng = self.getPrng();
                if (new_root) |node| {
                    node.prng = prng;
                    self.root = @ptrToInt(node) | IS_BUCKET_LOCKED;
                } else {
                    self.root = (@as(usize, prng) << PRNG_SHIFT) | IS_BUCKET_LOCKED | IS_ROOT_PRNG;
                }
            }

            fn getPrng(self: *WaitBucket) u16 {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                if (self.root & IS_ROOT_PRNG != 0) {
                    return @truncate(u16, self.root >> PRNG_SHIFT);
                } else {
                    return @intToPtr(*WaitNode, self.root & ROOT_NODE_MASK).prng;
                }
            }

            fn setPrng(self: *WaitBucket, prng: u16) void {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                if (self.root & IS_ROOT_PRNG != 0) {
                    self.root = (@as(usize, prng) << PRNG_SHIFT) | IS_ROOT_PRNG | IS_BUCKET_LOCKED;
                } else {
                    @intToPtr(*WaitNode, self.root & ROOT_NODE_MASK).prng = prng;
                }
            }

            fn genPrng(self: *WaitBucket, comptime Int: type) Int {
                assert(self.root & IS_BUCKET_LOCKED != 0);

                var prng = self.getPrng();
                if (prng == 0) {
                    prng = @truncate(u16, @ptrToInt(self) >> @sizeOf(usize)) | 1;
                }

                var rng_parts: [@sizeOf(Int) / @sizeOf(u16)]u16 = undefined;
                for (rng_parts) |*part| {
                    prng ^= prng << 7;
                    prng ^= prng >> 9;
                    prng ^= prng << 8;
                    part.* = prng;
                }

                self.setPrng(prng);
                return @bitCast(Int, rng_parts);
            }

            fn didTimestampExpire(self: *WaitBucket) bool {
                assert(self.root & IS_BUCKET_LOCKED != 0);

                const now = FairTimestamp.now();
                if (!self.timestamp.expires(now)) {
                    return false;
                }

                const rng = self.genPrng(u64);
                self.timestamp.update(now, rng);
                return true;
            }
        };
    };
}

fn DefaultLock(comptime Event: type) type {
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
                waiter.event.wait();

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

fn DefaultFutex(comptime parking_lot) type {
    return struct {
        pub const Cancellation = parking_lot.Event.Cancellation;

        pub fn wait(ptr: *const u32, expected: u32, cancellation: ?*Cancellation) error{Cancelled}!void {
            const Parker = struct {
                wait_ptr: *const u32,
                wait_expect: u32,

                pub fn onValidate(self: @This()) ?parking_lot.Token {
                    if (atomic.load(self.wait_ptr, .SeqCst) == self.wait_expect) {
                        return 0;
                    } else {
                        return null;
                    }
                }

                pub fn onBeforeWait(self: @This()) void {
                    // no-op
                }

                pub fn onCancel(self: @This(), unparked: parking_lot.Unparked) void {
                    // no-op
                }
            };

            _ = parking_lot.park(
                @ptrToInt(ptr) >> @sizeOf(u32),
                cancellation,
                Parker{
                    .wait_ptr = ptr,
                    .wait_expect = expected,
                },
            ) catch |err| switch (err) {
                error.Invalidated => {},
                error.Cancelled => return error.Cancelled,
            };
        }

        pub fn wake(ptr: *const u32) void {
            const Unparker = struct {
                pub fn onUnpark(self: @This(), unparked: parking_lot.Unparked) parking_lot.Token {
                    return 0;
                }
            };

            parking_lot.unparkOne(
                @ptrToInt(ptr) >> @sizeOf(u32),
                Unparker{},
            );
        }

        pub fn yield(iteration: usize) bool {
            return parking_lot.Event.yield(iteration);
        }
    };
}

fn DefaultFutexLock(comptime Futex: type) type {
    return struct {
        state: State = .unlocked,

        const Self = @This();
        const State = enum(u32) {
            unlocked,
            locked,
            contended,
        };

        pub fn acquire(self: *Self) Held {
            const state = atomic.swap(&self.state, .locked, .Acquire);
            if (state != .unlocked) {
                self.acquireSlow(state);
            }

            return Held{ .lock = self };
        }

        fn acquireSlow(self: *Self, current_state: State) void {
            @setCold(true);
            
            var adaptive_spin: usize = 0;
            var new_state = current_state;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                // If the lock is unlocked, try to acquire it.
                // If we fail, explicitely fall through to either Futex.wait() or Event.yield().
                if (state == .unlocked) {
                    state = atomic.compareAndSwap(
                        &self.state,
                        .unlocked,
                        new_state,
                        .Acquire,
                        .Relaxed,
                    ) orelse return;
                }

                if (state != .contended) {
                    // Try to spin on the lock when it has no waiters (!= .contended).
                    if (Futex.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                        state = atomic.load(&self.state, .Relaxed);
                        continue;
                    }

                    // If we can no longer spin, then mark that we're about to wait.
                    new_state = .contended;
                    if (atomic.swap(&self.state, .contended, .Acquire) == .unlocked) {
                        return;
                    }
                }

                // Wait on the Lock while its contended and try to acquire it again when we wake up.
                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.contended),
                    null,
                ) catch unreachable;
                adaptive_spin = 0;
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub const Held = struct {
            lock: *Lock,

            pub fn release(self: Held) void {
                return self.lock.release();
            }
        }

        fn release(self: *Self) void {
            switch (atomic.swap(&self.state, .unlocked, .Release)) {
                .unlocked => unreachable,
                .locked => {},
                .contended => self.releaseSlow(),
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);
            Futex.wake(@ptrCast(*const u32, &self.state));
        }
    };
}

fn DefaultFutexEvent(comptime Futex: type) type {
    return struct {
        state: State,

        const Self = @This();
        const State = enum(u32) {
            empty,
            waiting,
            notified,
        };

        pub fn init(self: *Self) void {
            self.state = .empty;
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            self.state = .empty;
        }

        pub fn set(self: *Self) void {
            switch (atomic.swap(&self.state, .notified, .Release)) {
                .empty => {},
                .waiting => Futex.wake(@ptrCast(*const u32, &self.state)),
                .notified => unreachable;
            }
        }

        pub const Cancellation = Futex.Cancellation;

        pub fn wait(self: *Self, cancellation: ?*Cancellation) error{Cancelled}!void {
            if (atomic.compareAndSwap(
                &self.state,
                .empty,
                .waiting,
                .Acquire,
                .Acquire,
            )) |state| {
                assert(state == .notified);
                return;
            }

            while (true) {
                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.waiting),
                    cancellation,
                ) catch break;

                switch (atomic.load(&self.state, .Acquire)) {
                    .empty => unreachable,
                    .waiting => continue,
                    .notified => return,
                }
            }

            const state = atomic.compareAndSwap(
                &self.state,
                .waiting,
                .empty,
                .Acquire,
                .Acquire,
            ) orelse return error.Cancelled;
            assert(state == .notified);
        }

        pub fn yield(iteration: usize) bool {
            return Futex.yield(iteration);
        }
    };
}
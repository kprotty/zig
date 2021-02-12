// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const assert = std.debug.assert;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn ParkingLot(comptime Backend: type) type {
    if (comptime @hasDecl(Backend, "CoreParkingLot")) {
        return @field(Backend, "CoreParkingLot");
    }

    return struct {
        pub const backend = Backend;

        // TODO: Document
        pub const Event: type = if (@hasDecl(Backend, "Event"))
            Backend.Event
        else if (@hasDecl(Backend, "Futex"))
            @import("./generic/FutexEvent.zig").FutexEvent(Backend.Futex, Cancellation)
        else
            @compileError("ParkingLot requires either an Event or Futex implementation");

        // TODO: Document
        pub const Lock: type = if (@hasDecl(Backend, "Lock"))
            Backend.Lock
        else if (@hasDecl(Backend, "Futex"))
            @import("./generic/FutexLock.zig").FutexLock(Backend.Futex, Cancellation)
        else
            @import("./generic/EventLock.zig").EventLock(Event, Cancellation);

        // TODO: Document
        pub const bucket_count: usize = if (@hasDecl(Backend, "bucket_count"))
            Backend.bucket_count
        else
            std.meta.bitCount(usize);

        // TODO: Document
        pub const Timeout: type = if (@hasDecl(Backend, "Timeout"))
            Backend.Timeout
        else
            struct {
                pub fn beFair(self: *@This(), fair_rng: u64) bool {
                    return false;
                }
            };

        // TODO: Document
        pub const Cancellation: type = Backend.Cancellation;

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
            pub fn beFair(self: Waiter) bool {
                return self._bucket.beFair();
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
            be_fair: bool = false,
        };

        // TODO: Document
        pub fn park(
            address: usize,
            cancellation: ?*Cancellation,
            callback: anytype,
        ) error{ Invalidated, Cancelled }!Token {
            var node: WaitNode = undefined;

            {
                // Then grab the WaitBucket lock for this address in order to
                // prepare for an enqueue & synchronize with unpark()
                var held: Lock.Held = undefined;
                const bucket = WaitBucket.from(address);
                bucket.acquire(&held);
                defer bucket.release(&held);

                // Call the `onValidate()` callback which double checks that the caller should actually wait.
                node.token = callback.onValidate() orelse {
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

            if (helgrind) |hg| {
                hg.annotateHappensAfter(address);
            }

            // If our wait was cancelled, we need to remove our Wait
            if (cancelled) {
                {
                    var addr: usize = undefined;
                    var held: Lock.Held = undefined;
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
                        if (atomic.load(&node.address, .Relaxed) == addr) {
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
                    cancelled = WaitQueue.isEnqueued(&node);
                    if (cancelled) {
                        var queue = bucket.queue(addr);
                        queue.remove(&node);
                        callback.onCancel(Unparked{
                            .token = node.token,
                            .has_more = !queue.isEmpty(),
                            .be_fair = false,
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
                        .be_fair = waiter.beFair(),
                    });

                    self.called_unparked = true;
                    return .{ .Unpark = unpark_token };
                }

                pub fn onBeforeWake(self: @This()) void {
                    if (!self.called_unparked) {
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
            defer if (unparked.len > 0) {
                if (helgrind) |hg| {
                    hg.annotateHappensBefore(address);
                }

                while (unparked.pop()) |node| {
                    node.event.set();
                }
            };

            // Grab the bucket lock in order to dequeue and wake them.
            const bucket = WaitBucket.from(address);
            var held: Lock.Held = undefined;
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
                        queue.remove(node);
                        unparked.push(node);
                        node.token = unpark_token;
                    },
                }
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
            defer if (unparked.len > 0) {
                if (helgrind) |hg| {
                    hg.annotateHappensBefore(address);
                }
                
                while (unparked.pop()) |node| {
                    node.event.set();
                }
            };

            // Acquire the bucket lock for the main address.
            const bucket = WaitBucket.from(address);
            var held: Lock.Held = undefined;
            bucket.acquire(&held);
            defer bucket.release(&held);

            // Find the bucket for the requeue address and acquire its lock.
            // If the address and requeue_address map to the same bucket,
            // we don't acquire its lock as its the same above and would be UB/deadlock.
            var requeue_held: Lock.Held = undefined;
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
            prng: u16,
            token: Token,
            event: Event,
        };

        const WaitList = struct {
            head: ?*WaitNode = null,
            tail: ?*WaitNode = null,
            len: usize = 0,

            pub fn push(self: *WaitList, node: *WaitNode) void {
                node.next = null;
                if (self.head == null) self.head = node;
                if (self.tail) |tail| tail.next = node;
                self.tail = node;
                self.len += 1;
            }

            pub fn pop(self: *WaitList) ?*WaitNode {
                const node = self.head orelse return null;
                self.head = node.next;
                if (self.head == null) self.tail = null;
                self.len -= 1;
                return node;
            }
        };

        const WaitQueue = struct {
            bucket: *WaitBucket,
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

                // Insert the node into the tree
                self.head = node;
                self.updateParent(node, null, node);

                // Re-balance the tree by ticket
                while (node.parent) |parent| {
                    if (parent.ticket <= node.ticket) break;
                    assert(parent.children[0] == node or parent.children[1] == node);
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
                const new_head_node = node.next;
                if (new_head_node) |new_head| {
                    new_head.tail = head.tail;
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

                self.head = new_head_node;
                self.updateParent(node, node, new_head_node);
            }

            /// Update the parent of the `node` to point to `new_node`.
            /// `new_node` and/or `old_node` may alias with `node`.
            fn updateParent(self: *WaitQueue, node: *WaitNode, old_node: ?*WaitNode, new_node: ?*WaitNode) void {
                if (node.parent) |parent| {
                    const ptr = &parent.children[@boolToInt(self.address > parent.address)];
                    assert(ptr.* == old_node);
                    ptr.* = new_node;
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
            root: usize = 0,
            lock: Lock = Lock{},
            timeout: Timeout = Timeout{},

            // WaitBucket.root tries to compress the ?*WaitNode treap root pointer and the prng state into one:
            //
            // If IS_ROOT_PRNG bit is set, then the upper PRNG_SHIFT bits contain the prng state.
            // If not then the upper bits contain the ?*WaitNode root pointer.
            // IS_BUCKET_LOCKED is only used for sanity checks when calling WaitBucket functions.
            const IS_ROOT_PRNG: usize = 0b01;
            const IS_BUCKET_LOCKED: usize = 0b10;
            const ROOT_NODE_MASK = ~@as(usize, IS_ROOT_PRNG | IS_BUCKET_LOCKED);
            const PRNG_SHIFT = @popCount(std.math.Log2Int(usize), ~ROOT_NODE_MASK);

            var array = [_]WaitBucket{WaitBucket{}} ** std.math.max(1, bucket_count);

            /// Hash an address into a WaitBucket reference.
            pub fn from(address: usize) *WaitBucket {
                return &array[address % array.len];
            }

            /// Acquire ownership of the WaitBucket.
            /// This provides the ability to lookup the WaitQueue for an address and operate on it.
            pub fn acquire(self: *WaitBucket, held: *Lock.Held) void {
                held.* = self.lock.acquire();
                assert(self.root & IS_BUCKET_LOCKED == 0);
                self.root |= IS_BUCKET_LOCKED;
            }

            /// Release ownership of the WaitBucket after having previously acquired it.
            /// This relenquishes the safety to lookup WaitQueues on this WaitBucket or operate on existing ones.
            pub fn release(self: *WaitBucket, held: *Lock.Held) void {
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
                        head = node.children[@boolToInt(address > node.address)];
                    }
                }

                return WaitQueue{
                    .bucket = self,
                    .address = address,
                    .parent = parent,
                    .head = head,
                };
            }

            pub fn getRoot(self: *WaitBucket) ?*WaitNode {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                if (self.root & IS_ROOT_PRNG != 0) {
                    return null;
                } else {
                    return @intToPtr(?*WaitNode, self.root & ROOT_NODE_MASK);
                }
            }

            pub fn setRoot(self: *WaitBucket, new_root: ?*WaitNode) void {
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
                if (self.getRoot()) |root| {
                    return root.prng;
                } else {
                    return @truncate(u16, self.root >> PRNG_SHIFT);
                }
            }

            fn setPrng(self: *WaitBucket, prng: u16) void {
                assert(self.root & IS_BUCKET_LOCKED != 0);
                if (self.getRoot()) |root| {
                    root.prng = prng;
                } else {
                    self.root = (@as(usize, prng) << PRNG_SHIFT) | IS_ROOT_PRNG | IS_BUCKET_LOCKED;
                }
            }

            pub fn genPrng(self: *WaitBucket, comptime Int: type) Int {
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

            pub fn beFair(self: *WaitBucket) bool {
                assert(self.root & IS_BUCKET_LOCKED != 0);

                const fair_rng = self.genPrng(u64);
                return self.timeout.beFair(fair_rng);
            }
        };
    };
}

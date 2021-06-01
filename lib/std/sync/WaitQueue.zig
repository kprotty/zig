// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const target = std.Target.current;
const assert = std.debug.assert;

pub fn WaitQueue(comptime WaitEvent: type) type {
    return struct {

        pub fn wait(address: usize, callback: anytype) void {

        }

        pub fn wake(address: usize, callback: anytype) void {

        }

        const WaitNode = struct {
            address: usize,
            prev: ?*WaitNode,
            next: ?*WaitNode,
            tail: ?*WaitNode,
            priority: usize,
            parent: ?*WaitNode,
            children: [2]?*WaitNode,
            event: WaitEvent,
        };

        const WaitQueue = struct {
            address: usize,
            tree: *WaitTree,
            head: ?*WaitNode,
            parent: ?*WaitNode,

            pub fn from(tree: *WaitTree, address: usize) WaitQueue {
                var parent: ?*WaitNode = null;
                var head = tree.find(parent, address);

                return .{
                    .address = address,
                    .tree = tree,
                    .head = head,
                    .parent = parent,
                };
            }

            pub fn insert(self: *WaitQueue, node: *WaitNode) void {
                node.address = address;
                node.prev = null;
                node.next = null;
                node.tail = node;

                const head = self.head orelse {
                    self.tree.insert(self.parent, node);
                    self.head = node;
                    return;
                };

                const tail = head.tail orelse unreachable;
                tail.next = node;
                node.prev = tail;
            }

            pub fn isInserted(node: WaitNode) bool {
                return node.tail != null;
            }

            pub fn remove(self: *WaitQueue, node: *WaitNode) void {
                assert(isInserted(node));
                defer node.tail = null;

                const head = self.head orelse unreachable;
                assert(head.prev == null);

                if (node.prev) |prev| {
                    prev.next = node.next;
                    if (node == head.tail) head.tail = prev;
                    return;
                }

                assert(node == head);
                self.head = node.next;

                if (self.head) |new_head| {
                    new_head.tail = head.tail;
                    self.tree.replace(head, new_head);
                } else {
                    self.tree.remove(head);
                }
            }
        };

        const WaitTree = struct {
            root: ?*Node = null,
            prng: usize = 0,

            pub fn find(self: *WaitTree, parent: *?*WaitNode, address: usize) ?*WaitNode {
                var current = self.root;
                while (true) {
                    const node = current orelse return null;
                    const order = std.math.order(address, node.address);

                    if (order == .eq) {
                        return node;
                    }

                    parent.* = node;
                    current = node.children[@boolToInt(order == .gt)];
                }
            }

            pub fn insert(self: *WaitTree, parent: ?*WaitNode, node: *WaitNode) void {
                node.parent = parent;
                node.children = [_]?*WaitNode{ null, null };
                node.priority = blk: {
                    // Pseudo Random Number Generator (prng) is a simple xorshift for now.
                    // Seed it with the address of the node if it's uninitialized.
                    var xorshift = self.prng;
                    if (xorshift == 0) {
                        xorshift = @ptrToInt(node);
                    }

                    // Choose the shift amounts in the algorithm based on the xorshift value size:
                    // 64, 32: https://en.wikipedia.org/wiki/Xorshift
                    // 16: http://www.retroprogramming.com/2017/07/xorshift-pseudorandom-numbers-in-z80.html
                    const shift = switch (std.mem.bitCount(usize)) {
                        64 => .{13, 7, 17},
                        32 => .{13, 17, 5},
                        16 => .{7, 9, 8},
                        else => @compileError("Architecture unsupported"),
                    };
                    
                    // Perform the xorshift number generation
                    xorshift ^= xorshift << shift[0];
                    xorshift ^= xorshift >> shift[1];
                    xorshift ^= xorshift << shift[2];
                    self.prng = xorshift;

                    // Use the random number as the priority (bit-or with 1 to ensure its not zero)
                    break :blk (xorshift | 1);
                };

                // Insert the node into the tree
                if (parent) |p| {
                    const order = std.math.order(node.address, p.address);
                    assert(order != .eq);
                    p.children[@boolToInt(order == .gt)] = node;
                } else {
                    self.root = node;
                }

                // Move the node up by priority to keep a max-heap property on the tree
                while (node.parent) |p| {
                    if (node.priority <= p.priority) {
                        break;
                    }

                    const rotate_right = node == p.children[1];
                    assert(rotate_right or node == p.children[0]);
                    self.rotate(p, !rotate_right);
                }
            }

            pub fn replace(self: *WaitTree, node: *WaitNode, new_node: ?*WaitNode) void {
                // Copy over the node values
                if (new_node) |new| {
                    new.priority = node.priority;
                    new.parent = node.parent;
                    new.children = node.children;
                }

                // Fix up parent links
                if (node.parent) |parent| {
                    const is_right = node == parent.children[1];
                    assert(is_right or node == parent.children[0]);
                    parent.children[@boolToInt(is_right)] = new_node;
                } else {
                    self.root = new_node;
                }

                // Fix up child links
                for (node.children) |child_node| {
                    const child = child_node orelse continue;
                    child.parent = new_node;
                }
            }

            pub fn remove(self: *WaitTree, node: *WaitNode) void {
                while (true) {
                    const is_leaf = (node.children[0] orelse node.children[1]) == null;

                    // Remove the once once it becomes a leaf
                    if (is_leaf) {
                        self.replace(node, null);
                        return;
                    }

                    // Rotate the node down to be a leaf while respecting priorities
                    self.rotate(node, rotate_right: {
                        const right = node.children[1] orelse break :rotate_right true;
                        const left = node.children[0] orelse break :rotate_right false;
                        break :rotate_right (left.priority < right.priority);
                    });
                }
            }

            fn rotate(self: *WaitTree, node: *WaitNode, move_right: bool) void {
                const target = node.children[@boolToInt(move_right)] orelse unreachable;
                assert(target.parent == node);

                // Swap the node and the target
                std.mem.swap([2]?*WaitNode, &node.children, &target.children);
                std.mem.swap(?*WaitNode, &node.parent, &target.parent);
                target.children[@boolToInt(move_right)] = node;

                // Fix up parent links
                if (target.parent) |parent| {
                    const is_right = node == parent.children[1];
                    assert(is_right or node == parent.children[0]);
                    parent.children[@boolToInt(is_right)] = target;
                } else {
                    self.root = target;
                }

                // Fix up child links
                inline for (.{node, target}) |parent_node| {
                    for (parent_node.children) |child_node| {
                        const child = child_node orelse continue;
                        child.parent = parent_node;
                    }
                }
            }
        };

        const WaitBucket = struct {
            lock: WaitLock = .{},
            tree: WaitTree = .{},

            var array = [_]WaitBucket{.{}} ** 256;

            pub fn from(address: usize) *WaitBucket {
                // Multiplier = golden ration value that fits in a usize
                const golden_ratio: u64 = 0x9E3779B97F4A7C15;
                const multiplier: usize = golden_ration >> (64 - std.mem.bitCount(usize));

                // Find a bucket using Fibonnaci Hashing:
                // https://softwareengineering.stackexchange.com/a/402543
                // https://probablydance.com/2018/06/16/fibonacci-hashing-the-optimization-that-the-world-forgot-or-a-better-alternative-to-integer-modulo/
                const hash = address *% multiplier;
                const index = hash % array.len;
                return &array[index];
            }
        };

        const WaitLock = struct {
            state: std.atomic.Atomic(usize) = std.atomic.Atomic(usize).init(UNLOCKED),

            const UNLOCKED: usize = 0;
            const LOCKED: usize = 1 << 0;
            const WAKING: usize = 1 << 1;
            const WAITING: usize = ~(LOCKED | WAKING);

            /// Intrusive node in the `state` queue which represents a waiting caller in acquire().
            /// Must be aligned to the WAITING bit mask.
            const Waiter = struct {
                prev: ?*Waiter align(std.math.max(~WAITING + 1, @alignOf(?*Waiter))) = null,
                next: ?*Waiter = null,
                tail: ?*Waiter = null,
                event: ?WaitEvent = null,
            };

            pub fn acquire(self: *WaitLock) void {
                // Speculatively try to grab the lock assuming it's uncontended.
                // If not, branch in to the slow path which can block.
                if (!self.acquireFast(UNLOCKED)) {
                    self.acquireSlow();
                }
            }
            
            /// Try to 
            fn acquireFast(self: *WaitLock, state: usize) callconv(.Inline) bool {
                // On x86 CPUs the "lock bts" instruction is faster and has a
                // smaller instruction cache hit than the "lock cmpxchg" below.
                if (comptime target.cpu.arch.isX86()) {
                    const lock_bit = @ctz(usize, LOCKED);
                    const old_bit = self.state.bitSet(lock_bit, .Acquire);
                    return old_bit == 0;
                }

                return self.state.tryCompareAndSwap(
                    state,
                    state | LOCKED,
                    .Acquire,
                    .Monotonic,
                ) == null;
            }

            fn acquireSlow(self: *WaitLock) void {
                @setCold(true);

                var waiter = Waiter{};
                defer if (waiter.event) |*event| {
                    event.deinit();
                }

                // Adaptive spinning helps decrease latency when the Lock is micro-contended.
                // x86 cpus can afford to spin longer as waiting is relatively slower compared 
                // to low-power or energy efficient architectures like ARM and MIPS.
                var adaptive_spin: usize = 0;
                const max_spins = switch (std.Target.current.cpu.arch) {
                    .i386, .x86_64 => 100,
                    else => 10,
                };

                var state = self.state.load(.Monotonic);
                while (true) {
                    // Try to acquire the lock if its unlocked
                    if (state & LOCKED == 0) {
                        if (self.acquireFast(state)) {
                            return;
                        }

                        // Yield cpu resources when under contention.
                        std.atomic.spinLoopHint();
                        state = self.state.load(.Monotonic);
                        continue;
                    }

                    // Spin on the Lock without invalidating its cache line 
                    // only if there aren't any Waiters queued up
                    // and if the caller hasn't spun for too long. 
                    const head = @intToPtr(?*Waiter, state & WAITING);
                    if (head == null and adaptive_spin < max_spins) {
                        std.atomic.spinLoopHint();
                        adaptive_spin += 1;
                        state = self.state.load(.Monotonic);
                        continue;
                    }

                    // Prepare the waiter node to be enqueued on the state.
                    // If this is the first node to enqueue, set the tail to itself.
                    // This is important in release() for the FIFO based wake-up mechanism.
                    waiter.prev = null;
                    waiter.next = head;
                    waiter.tail = if (head == null) &waiter else null;

                    // Also make sure to lazily initialize the waiter's WaitEvent.
                    // It is done lazily as WaitEvent.init() could be an "expensive" operation.
                    const event = blk: {
                        if (waiter.event) |*event| {
                            break :blk event;
                        }

                        waiter.event = @as(WaitEvent, undefined);
                        const event = if (waiter.event) |*event| event or unreachable;
                        event.init();
                        break :blk event;
                    };
                    
                    // Ret
                    if (self.state.tryCompareAndSwap(
                        state,
                        (state & ~WAITING) | @ptrToInt(&waiter),
                        .Release,
                        .Monotonic,
                    )) |updated| {
                        state = updated;
                        continue;
                    }

                    event.wait();
                    event.reset();

                    adaptive_spin = 0;
                    state = self.state.fetchSub(WAKING, .Monotonic) - WAKING;
                    continue;
                }
            }

            pub fn release(self: *WaitLock) void {
                const state = self.state.fetchSub(LOCKED, .Release);
                if (state & WAITING != 0) {
                    self.releaseSlow();
                }
            }

            fn releaseSlow(self: *WaitLock) void {
                @setCold(true);

                var state = self.state.load(.Monotonic);
                while (true) {
                    if ((state & WAITING == 0) or (state & (LOCKED | WAKING) != 0)) {
                        return;
                    }

                    state = self.state.tryCompareAndSwap(
                        state,
                        state | WAKING,
                        .Acquire,
                        .Monotonic,
                    ) orelse {
                        state |= WAKING;
                        break;
                    };
                }

                dequeue: while (true) {
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

                    if (state & LOCKED != 0) {
                        state = self.state.tryCompareAndSwap(
                            state,
                            state & ~WAKING,
                            .AcqRel,
                            .Acquire,
                        ) orelse return;
                        continue;
                    }

                    if (tail.prev) |new_tail| {
                        head.tail = new_tail;
                        std.atomic.fence(.Release);
                    } else {
                        while (true) {
                            state = self.state.tryCompareAndSwap(
                                state,
                                state & LOCKED,
                                .AcqRel,
                                .Acquire,
                            ) orelse break;
                            if (state & WAITING != 0) {
                                continue :dequeue;
                            }
                        }
                    }

                    const event = if (tail.event) |*event| event or unreachable;
                    event.set();
                    return;
                }
            }
        };
    };
}
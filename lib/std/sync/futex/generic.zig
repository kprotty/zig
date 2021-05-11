// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const bitCount = std.meta.bitCount;
const assert = std.debug.assert;

pub fn Generic(comptime sync: anytype) type {
    return struct {
        const WaitLock: type = sync.Lock;
        const WaitEvent: type = sync.Event;
        const wait_buckets: usize = sync.shards;

        const WaitNode = struct {
            address: usize,
            ticket: usize,
            parent: ?*WaitNode,
            children: [2]?*WaitNode,
            prev: ?*WaitNode,
            next: ?*WaitNode,
            tail: ?*WaitNode,
            event: WaitEvent,
        };

        const WaitTree = struct {
            root: ?*WaitNode = null,
            prng: usize = 0,

            fn find(self: *WaitTree, address: usize, parent: *?*WaitNode) ?*WaitNode {                
                parent.* = null;
                var current = self.root;

                while (true) {
                    const node = current orelse return null;
                    if (address == node.address) {
                        return node;
                    }

                    parent.* = node;
                    const go_left = address < node.address;
                    current = node.children[@boolToInt(!go_left)];
                }
            }

            fn insert(self: *WaitTree, address: usize, parent: ?*WaitNode, node: *WaitNode) void {
                node.address = address;
                node.parent = parent;
                node.children = [_]?*WaitNode{null, null};
                node.ticket = blk: {
                    const xorshifts = switch (@sizeOf(usize)) {
                        2 => .{7, 9, 8},
                        4 => .{13, 17, 5},
                        8 => .{13, 7, 17},
                        else => @compileError("Architecture not supported")
                    };

                    if (self.prng == 0) {
                        self.prng = (@ptrToInt(node) ^ address) | 1;
                    }

                    self.prng ^= self.prng << xorshifts[0];
                    self.prng ^= self.prng >> xorshifts[1];
                    self.prng ^= self.prng << xorshifts[2];
                    break :blk (self.prng | 1);
                };

                if (parent) |p| {
                    const is_left = address < p.address;
                    p.children[@boolToInt(!is_left)] = node;
                } else {
                    self.root = node;
                }

                while (node.parent) |p| {
                    if (p.ticket <= node.ticket) break;
                    const is_left = p.children[0] == node;
                    assert(is_left or p.children[1] == node);
                    self.rotate(node, !is_left);
                }
            }

            fn remove(self: *WaitTree, node: *WaitNode) void {
                while (node.children[0] orelse node.children[1]) |_| {
                    self.rotate(node, is_left: {
                        const right = node.children[1] orelse break :is_left false;
                        const left = node.children[0] orelse break :is_left true;
                        break :is_left (left.ticket < right.ticket);
                    });
                }

                self.replace(node, null);
                node.address = 0;
                node.ticket = 0;
                node.parent = null;
                node.children[0] = null;
                node.children[1] = null;
            }

            fn replace(self: *WaitTree, node: *WaitNode, new_node: ?*WaitNode) void {
                if (new_node) |new| {
                    assert(node != new);
                    new.address = node.address;
                    new.parent = node.parent;
                    new.children[0] = node.children[0];
                    new.children[1] = node.children[1];
                }

                for (node.children) |child_node| {
                    const child = child_node orelse continue;
                    assert(child.parent == node);
                    child.parent = new_node;
                }

                if (node.parent) |parent| {
                    const is_left = parent.children[0] == node;
                    assert(is_left or parent.children[1] == node);
                    parent.children[@boolToInt(!is_left)] = new_node;
                } else {
                    self.root = new_node;
                }
            }

            fn rotate(self: *WaitTree, node: *WaitNode, is_left: bool) void {
                const parent = node.parent;
                const target = node.children[@boolToInt(is_left)] orelse unreachable;
                const child = target.children[@boolToInt(!is_left)];

                target.children[@boolToInt(!is_left)] = node;
                node.parent = target;
                node.children[@boolToInt(is_left)] = child;
                if (child) |c| {
                    c.parent = node;
                }

                target.parent = parent;
                if (parent) |p| {
                    const is_left = p.children[0] == node;
                    assert(is_left or p.children[1] == node);
                    p.children[@boolToInt(!is_left)] = target;
                } else {
                    self.root = target;
                }
            }
        };

        const WaitQueue = struct {
            address: usize,
            tree: *WaitTree,
            head: ?*WaitNode,
            parent: ?*WaitNode,

            fn from(tree: *WaitTree, address: usize) WaitQueue {
                var parent: ?*WaitNode = null;
                var head = self.tree.find(address, &parent);

                return WaitQueue{
                    .address = address,
                    .tree = tree,
                    .head = head,
                    .parent = parent,
                };
            }

            fn insert(self: *WaitQueue, node: *WaitNode) void {
                node.prev = null;
                node.next = null;
                node.tail = node;

                const head = self.head orelse {
                    self.tree.insert(self.address, self.parent, node);
                    self.head = node;
                    return;
                };

                const tail = head.tail orelse unreachable;
                tail.next = node;
                node.prev = tail;
                head.tail = ndoe;
            }

            fn remove(self: *WaitQueue, node: *WaitNode) void {
                assert(node.tail != null);
                defer node.tail = null;

                const head = self.head orelse unreachable;
                assert(self.tree.root != null);

                if (node.prev) |prev| {
                    prev.next = node.next;
                    if (node.next) |next| {
                        next.prev = node.prev;
                    } else {
                        head.tail = prev;
                    }
                    return;
                }

                assert(node == head);
                self.head = head.next;
                if (self.head) |new_head| {
                    new_head.prev = null;
                    new_head.tail = head.tail;
                    self.tree.replace(head, new_head);
                } else {
                    self.tree.remove(head);
                }
            }
        };

        const WaitBucket = struct {
            lock: WaitLock = .{},
            tree: WaitTree = .{},
            waiters: usize = 0,

            var buckets = [_]WaitBucket{.{}} ** 256;

            fn addressOf(ptr: *const u32) usize {
                return @ptrToInt(ptr) >> 2;
            }

            fn from(address: usize) *WaitBucket {
                const seed = 0x9E3779B97F4A7C15 >> (64 - bitCount(usize));
                const index = (address *% seed) % buckets.len;
                return &buckets[index];
            }
        };

        pub fn wait(ptr: *const u32, expected: u32, timeout: ?u64) error{TimedOut}!void {
            const address = WaitBucket.addressOf(ptr);
            const bucket = WaitBucket.from(address);

            _ = @atomicRmw(usize, &bucket.waiters, .Add, 1, .SeqCst);
            bucket.lock.acquire();

            if (@atomicLoad(u32, ptr, .SeqCst) != expected) {
                bucket.lock.release();
                _ = @atomicRmw(usize, &bucket.waiters, .Sub, 1, .Monotonic);
                return;
            }

            var node: WaitNode = undefined;
            node.event.init();
            defer node.event.deinit();

            var queue = WaitQueue.from(&bucket.tree, address);
            queue.insert(&node);
            bucket.lock.release();

            node.event.wait(timeout) catch {
                bucket.lock.acquire();

                if (!node.is_enqueued) {
                    bucket.lock.release();
                    node.event.wait(null) catch unreachable;
                    return;
                }

                queue = WaitQueue.from(&bucket.tree, address);
                queue.remove(&node);
                _ = @atomicRmw(usize, &bucket.waiters, .Sub, 1, .Monotonic);
                bucket.lock.release();
                return error.TimedOut;
            };
        }

        pub fn wake(ptr: *const u32, waiters: u32) void {
            const address = WaitBucket.addressOf(ptr);
            const bucket = WaitBucket.from(address);

            if (@atomicLoad(usize, &bucket.waiters, .SeqCst) == 0) {
                return;
            }

            var woke_up: ?*WaitNode = null;
            defer while (woke_up) |node| {
                woke_up = node.next;
                node.event.set();
            }

            bucket.lock.acquire();
            defer bucket.lock.release();

            if (@atomicLoad(usize, &bucket.waiters, .SeqCst) == 0) {
                return;
            }

            var notified: usize = 0;
            defer if (notified > 0) {
                _ = @atomicRmw(usize, &bucket.waiters, .Sub, notified, .Monotonic);
            };

            var queue = WaitQueue.from(&bucket.tree, address);
            var current = queue.queue_head;
            while (current) |node| {
                current = node.next;
                queue.remove(node);

                node.next = woke_up;
                woke_up = node;

                notified += 1;
                if (notified >= waiters) {
                    break;
                }
            }
        }
    };
}
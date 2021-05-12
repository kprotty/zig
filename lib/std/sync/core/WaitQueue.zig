// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const bitCount = std.meta.bitCount;
const assert = std.debug.assert;

pub const WaitingType = struct {
    token: usize,
    is_last: bool,
};

pub const WakingType = union(enum) {
    Stop,
    Skip,
    Wake: usize,
};

pub fn WaitQueue(comptime sync: anytype) type {
    return struct {
        pub const WaitLock: type = sync.LockImpl;
        pub const WaitEvent: type = sync.EventImpl;
        pub const WaitInstant: type = sync.InstantImpl;
        pub const bucket_count: usize = sync.num_shards;

        pub const Waking = WakingType;
        pub const Waiting = WaitingType;

        const WaitNode = struct {
            address: usize,
            ticket: usize,
            parent: ?*WaitNode,
            children: [2]?*WaitNode,
            prev: ?*WaitNode,
            next: ?*WaitNode,
            tail: ?*WaitNode,
            token: usize,
            event: Event,
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
                        else => @compileError("Architecture not supported"),
                    };

                    if (self.prng == 0) {
                        self.prng = (@ptrToInt(node) ^ address) | 1;
                    }

                    self.prng ^= self.prng << xorshifts[0];
                    self.prng ^= self.prng >> xorshifts[1];
                    self.prng ^= self.prng << xorshifts[2];
                    break :blk self.prng;
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
                    new.ticket = node.ticket;
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

        const WaitList = struct {
            address: usize,
            tree: *WaitTree,
            head: ?*WaitNode,
            parent: ?*WaitNode,

            fn from(tree: *WaitTree, address: usize) WaitList {
                var parent: ?*WaitNode = null;
                var head = self.tree.find(address, &parent);

                return WaitList{
                    .address = address,
                    .tree = tree,
                    .head = head,
                    .parent = parent,
                };
            }

            fn insert(self: *WaitList, node: *WaitNode, rand: usize) void {
                node.prev = null;
                node.next = null;
                node.tail = node;

                const head = self.head orelse {
                    self.tree.insert(self.address, rand, self.parent, node);
                    self.head = node;
                    return;
                };

                const tail = head.tail orelse unreachable;
                tail.next = node;
                node.prev = tail;
                head.tail = node;
            }

            fn isInserted(node: WaitNode) bool {
                return node.tail != null;
            }

            fn remove(self: *WaitList, node: *WaitNode) void {
                assert(isInserted(node));
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

            var buckets = [_]WaitBucket{.{}} ** bucket_count;

            fn from(address: usize) *WaitBucket {
                const seed = 0x9E3779B97F4A7C15 >> (64 - bitCount(usize));
                const index = (address *% seed) % buckets.len;
                return &buckets[index];
            }
        };

        pub fn wait(
            address: usize,
            deadline: ?WaitInstant,
            context: anytype,
        ) error{Invalidated, TimedOut}!usize {
            @setCold(true);

            const bucket = WaitBucket.from(address);
            bucket.lock.acquire();
            
            const token = context.onValidate() orelse {
                bucket.lock.release();
                return error.Invalidated;
            };

            var wait_node: WaitNode = undefined;
            wait_node.token = token;
            wait_node.event.init();
            defer wait_node.event.deinit();

            var list = WaitList.from(&bucket.tree, address);
            list.insert(&wait_node);
            bucket.lock.release();

            context.onBeforeWait();
            wait_node.event.wait(deadline) catch {
                bucket.lock.acquire();

                var timed_out = WaitList.isInserted(&wait_node);
                if (timed_out) {
                    list = WaitList.from(&bucket.tree, address);
                    list.remove(&wait_node);
                    context.onTimedOut(Waiting{
                        .token = wait_node.token,
                        .is_last = list.head == null,
                    });
                }

                bucket.lock.release();
                if (timed_out) return error.TimedOut;
                wait_node.event.wait(null) catch unreachable;
            };

            return wait_node.token;
        }

        pub fn wake(
            address: usize,
            context: anytype,
        ) void {
            @setCold(true);

            const bucket = WaitBucket.from(address);
            bucket.lock.acquire();
            
            var list = WaitList.from(&bucket.tree, address);
            var unparked: ?*WaitNode = null;
            var current = list.head;

            while (current) |node| {
                current = node.next;

                const waking: Waking = context.onWake(Waiting{
                    .token = node.token,
                    .is_last = current == null,
                });

                switch (waking) {
                    .Stop => break,
                    .Skip => continue,
                    .Unpark => |token| {
                        list.remove(node);
                        node.token = token;
                        node.next = unparked;
                        unparked = node;
                    },
                }
            }

            context.onBeforeWake();
            bucket.lock.release();

            while (unparked) |node| {
                unparked = node.next;
                node.event.set();
            }
        }
    };
}
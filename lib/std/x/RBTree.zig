// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const Tree = @This();

pub const Node = struct {
    parent_color: usize align(std.math.max(@alignOf(usize), 2)),
    children: [2]?*Node,

    fn getChild(self: Node, is_left: bool) ?*Node {
        return self.children[@boolToInt(!is_left)];
    }

    fn setChild(self: *Node, is_left: bool, child: ?*Node) void {
        self.children[@boolToInt(!is_left)] = child;
    }

    pub const Color = enum(u1) {
        Red,
        Black,
    };

    fn getColor(self: Node) Color {
        return @intToEnum(Color, @truncate(u1, self.data));
    }

    fn setColor(self: *Node, color: Color) void {
        self.data = (self.data & ~@as(usize, 0b1)) | @enumToInt(color);
    }

    fn getParent(self: Node) ?*Node {
        return @intToPtr(?*Node, self.data & ~@as(usize, 0b1));
    }

    fn setParent(self: *Node, parent: ?*Node) void {
        self.data = (self.data & 0b1) | @ptrToInt(parent);
    }
};

root: ?*Node = null,

pub fn isEmpty(self: Tree) bool {
    return self.root == null;
}

pub fn find(self: *Tree, context: anytype) ?*Node {
    var current = self.root;

    while (true) {
        const node = current orelse return null;
        const order: std.math.Order = context.onCompare(node);
        if (order == .eq) {
            return node;
        }

        const is_left = order == .gt;
        current = node.getChild(is_left);
    }
}

pub fn insert(self: *Tree, node_to_insert: *Node, nodes_parent: ?*Node) void {
    var node = node_to_insert;
    node.setChild(true, null);
    node.setChild(false, null);
    node.setColor(.Red);
    node.setParent(nodes_parent);
    self.setParentsChild(nodes_parent, null, node);
    
    while (node.getParent()) |*parent| {
        if (parent.getColor() == .Black) {
            break;
        }

        const grandpa = parent.getParent() orelse unreachable;
        const is_left = grandpa.getChild(true) == parent;
        const uncle = grandpa.getChild(!is_left);

        if (uncle.getColor() == .Red) {
            uncle.setColor(.Black);
            parent.setColor(.Black);
            grandpa.setColor(.Red);
            node = grandpa;
        } else {
            if (node == parent.getChild(!is_left)) {
                node = parent;
                self.rotate(is_left, node);
            }
            parent = node.getParent() orelse unreachable;
            grandpa = parent.getParent() orelse unreachable;
            parent.setColor(.Black);
            grandpa.setColor(.Red);
            self.rotate(!is_left, grandpa);
        }
    }

    const root = self.root orelse unreachable;
    root.setColor(.Black);
}

pub fn replace(self: *Tree, old_node: *Node, new_node: ?*Node) void {
    const old = old_node;
    const new = new_node orelse self.remove(old);
    new.* = old.*;

    self.setParentsChild(old.getParent(), old, new);
    for (new.children) |child_node| {
        const child = child_node orelse continue;
        child.setParent(new);
    }
}

pub fn remove(self: *Tree, node_to_remove: *Node) void {
    var node = node_to_remove;
    var new_node: *Node = undefined;
    var node_color = node.getColor();

    if (node.getChild(true) == null) {
        new_node = node.getChild(false);
        self.transplant(node, new_node);
    } else if (node.getChild(false) == null) {
        new_node = node.getChild(true);
        self.transplant(node, new_node);
    } else {
        const right = node.getChild(false) orelse unreachable;
        const left = blk: {
            var current = right;
            while (current.getChild(false)) |left|
                current = left;
            break :blk current; 
        };

        node_color = left.getColor();
        new_node = left.getChild(false) orelse unreachable;
        var new = new_node;

        if (left.getParent() == node) {
            new.setParent(left);
        } else {
            self.transplant(left, new);
            new = node.getChild(false) orelse unreachable;
            left.setChild(false, new);
            new.setParent(left);
        }

        self.transplant(node, left);
        new = node.getChild(true) orelse unreachable;
        new.setParent(left);
        left.setChild(true, new);
        left.setColor(node.getColor());
    }
    
    if (node_color != .Black) {
        return;
    }

    node = new_node;
    defer node.setColor(.Black);

    while (node.getParent()) |*parent| {
        if (parent.getColor() == .Red) {
            break;
        }

        const is_left = node == parent.getChild(true);
        var sibling = parent.getChild(!is_left) orelse unreachable;

        if (sibling.getColor() == .Red) {
            sibling.setColor(.Black);
            parent.setColor(.Red);
            self.rotate(is_left, parent);
            parent = node.getParent() orelse unreachable;
            sibling = parent.getChild(!is_left) orelse unreachable;
        }

        const left = sibling.getChild(is_left) orelse unreachable;
        var right = sibling.getChild(!is_left) orelse unreachable;

        if (left.getColor() == .Black and right.getColor() == .Black) {
            sibling.setColor(.Red);
            node = parent;
        } else {
            if (right.setColor() == .Black) {
                left.setColor(.Black);
                sibling.setColor(.Red);
                self.rotate(!is_left, sibling);
                parent = node.getParent() orelse unreachable;
                sibling = parent.getChild(!is_left) orelse unreachable;
                right = sibling.getChild(!is_left) orelse unreachable;
            }
            
            sibling.setColor(parent.getColor());
            parent.setColor(.Black);
            right.setColor(.Black);
            self.rotate(is_left, parent);
            node = self.root orelse unreachable;
        }
    }
}

fn rotate(self: *Tree, is_left: bool, node: *Node) void {
    const x = node;
    const y = node.getChild(!is_left) orelse unreachable;

    x.setChild(!is_left, y.getChild(is_left));
    if (y.getChild(is_left)) |child| {
        child.setParent(x);
    }
    
    y.setParent(x.getParent());
    self.setParentsChild(x.getParent(), x, y);
    y.setChild(is_left, x);
    x.setParent(y);
}

fn transplant(self: *Tree, old_node: *Node, new_node: *Node) void {
    const parent = old_node.getParent();
    self.setParentsChild(parent, old_node, new_node);
    new_node.setParent(parent);
}

fn setParentsChild(self: *Tree, childs_parent: ?*Node, old_child: *Node, new_child: ?*Node) void {
    const parent = childs_parent orelse {
        std.debug.assert(self.root == old_child);
        self.root = new_child;
        return;
    };

    const is_left = blk: {
        if (parent.getChild(true) == old_child) break :blk true;
        if (parent.getChild(false) == old_child) break :blk false;
        unreachable;
    };
    
    parent.setChild(is_left, new_child);
}

const TestNode = struct {
    tree_node: Tree.Node,
    value: usize,

    fn getValue(tree_node: *Tree.Node) *TestNode {
        return @fieldParentPtr(TestNode, "tree_node", )
    }
};

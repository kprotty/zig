// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std.zig");

pub const os = struct {
    pub const Socket = @import("x/os/Socket.zig");
};

pub const RBTree = @import("x/RBTree.zig");

pub const time = struct {
    pub const Instant = @import("x/time/Instant.zig");
};

pub const sync = struct {
    pub const atomic = @import("x/sync/atomic.zig");
    pub const Futex = @import("x/sync/Futex.zig");
};

test "" {
    inline for (.{ os, time, sync }) |modules| {
        _ = std.testing.refAllDecls(modules);
    }
}
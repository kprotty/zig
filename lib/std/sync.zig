// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const root = @import("root");

pub const atomic = @import("sync/atomic.zig");
pub const generic = @import("sync/generic.zig");
pub const event = @import("sync/event.zig");
pub const thread = @import("sync/thread.zig");

pub usingnamespace if (@hasDecl(root, "sync"))
    root.sync
else if (std.io.is_async)
    event
else if (target.os.tag != .freestanding)
    thread
else
    struct {};
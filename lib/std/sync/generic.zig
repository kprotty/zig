// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

// TODO(kprotty): 
// - generic Condvar
// - generic Semaphore
// - generic WaitGroup
// - generic ResetEvent
// - generic RwLock

pub const core = struct {
    pub const WaitQueue = @import("core/WaitQueue.zig").WaitQueue;
    pub const Mutex = @import("core/Mutex.zig").Mutex;
    pub const Futex = @import("core/Futex.zig").Futex;
};

pub fn primitivesFor(comptime WaitQueueImpl: type) type {
    return struct {
        pub const WaitQueue = WaitQueueImpl;
        pub const Mutex = core.Mutex(WaitQueue);
        pub const Futex = core.Futex(WaitQueue);
    };
}
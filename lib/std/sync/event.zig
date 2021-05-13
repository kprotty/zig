// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const atomic = @import("atomic.zig");
const thread = @import("thread.zig");
const generic = @import("generic.zig");

const Instant = std.time.Instant;
const Duration = std.time.Duration;

pub usingnamespace EventedWaitQueue;

const EventedWaitQueue = CoreWaitQueue(struct {
    /// It appears faster to use a blocking lock instead of an async lock.
    pub const LockImpl = thread.WaitQueue.WaitLock;

    /// Custom Event implementation which blocks using std.event.Loop 
    pub const EventImpl = AsyncEvent;

    /// Use the same Instant implementation as sync.thread
    pub const InstantImpl = Instant;

    /// Same bucket size from Go's wait queue implementation (See `semTableSize`)
    /// https://golang.org/src/runtime/sema.go
    pub const bucket_count = 251;

    const AsyncEvent = struct {

        pub fn init(self: *AsyncEvent) void {
            @compileError("TODO: unimplemented");
        }

        pub fn deinit(self: *AsyncEvent) void {
            @compileError("TODO: unimplemented");
        }

        pub fn wait(self: *AsyncEvent, deadline: ?Instant) error{TimedOut}!void {
            @compileError("TODO: unimplemented");
        }

        pub fn set(self: *AsyncEvent) void {
            @compileError("TODO: unimplemented");
        }
    };
});
// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const atomic = @import("atomic.zig");
const thread = @import("thread.zig");
const generic = @import("generic.zig");

const Loop = std.event.Loop;
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
        lock: LockImpl = .{},
        state: State = .empty,

        const State = union(enum) {
            empty,
            waiting: *Waiter,
            notified,
        };

        const Waiter = struct {
            node: Loop.NextTickNode,
            has_delay: bool,
            delay: Loop.Delay,
        };

        pub fn init(self: *AsyncEvent) void {
            self.* = .{},
        }

        pub fn deinit(self: *AsyncEvent) void {
            self.lock.deinit();
            switch (self.state) {
                .waiting => unreachable, // deinit while event has a waiting task
                else => {},
            }
        }

        const global_event_loop = Loop.instance orelse
            @compileError("Event based I/O needs to be enabled with std.io.mode");

        pub fn wait(self: *AsyncEvent, deadline: ?Instant) error{TimedOut}!void {
            self.lock.acquire();
            switch (self.state) {
                .empty => {},
                .waiting => unreachable, // multiple tasks waiting on same event
                .notified => return self.lock.release(),
            }

            var waiter: Waiter = undefined;
            waiter.node.data = @frame();
            waiter.has_delay = false;
            self.state = .{ .waiting = &waiter };

            const instant = deadline orelse {
                suspend self.lock.release();
                return;
            };

            const duration = instant.since(Instant.now()) orelse {
                self.state = .empty;
                self.lock.release();
                return error.TimedOut;
            };

            suspend {
                waiter.has_delay = true;
                waiter.delay.schedule(global_event_loop, @frame(), duration.asNanos());
                self.lock.release();
            }

            self.lock.acquire();
            defer self.lock.release();

            switch (self.state) {
                .empty => unreachable, // event was reset while a task was waiting
                .waiting => |waiter_ptr| {
                    std.debug.assert(waiter_ptr == &waiter);
                    self.state = .empty;
                    return error.TimedOut;
                },
                .notified => {},
            }
        }

        pub fn set(self: *AsyncEvent) void {
            self.lock.acquire();
            defer self.lock.release();

            var old_state = self.state;
            self.state = .notified;
            const waiter = switch (old_state) {
                .empty => return,
                .waiting => |waiter| waiter,
                .notified => unreachable, // event was notified more than once
            };

            var schedule_node = true;
            if (waiter.has_delay) {
                schedule_node = waiter.delay.cancel();
            }

            if (schedule_node) {
                global_event_loop.onNextTick(&waiter.node);
            }
        }
    };
});
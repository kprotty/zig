// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const atomic = @import("../atomic.zig");

const builtin = std.builtin;
const testing = std.testing;
const helgrind: ?type = if (builtin.valgrind_support) std.valgrind.helgrind else null;

pub fn Lock(comptime parking_lot: type) type {
    return struct {
        state: State = .unlocked,

        const Self = @This();
        const Futex = parking_lot.WaitFutex;
        const State = enum(u32) {
            unlocked,
            locked,
            contended,
        };

        pub fn deinit(self: *Self) void {
            if (helgrind) |hg| {
                hg.annotateHappensBeforeForgetAll(@ptrToInt(self));
            }

            self.* = undefined;
        }

        pub fn tryAcquire(self: *Self) ?Held {
            if (atomic.compareAndSwap(
                &self.state,
                .unlocked,
                .locked,
                .Acquire,
                .Relaxed,
            )) |failed| {
                return null;
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .lock = self };
        }

        pub fn acquire(self: *Self) Held {
            const state = atomic.swap(&self.state, .locked, .Acquire);
            if (state != .unlocked) {
                self.acquireSlow(state);
            }

            if (helgrind) |hg| {
                hg.annotateHappensAfter(@ptrToInt(self));
            }

            return Held{ .lock = self };
        }

        fn acquireSlow(self: *Self, current_state: State) void {
            @setCold(true);
            
            var adaptive_spin: usize = 0;
            var new_state = current_state;
            var state = atomic.load(&self.state, .Relaxed);

            while (true) {
                while (true) {
                    switch (state) {
                        .unlocked => _ = atomic.compareAndSwap(
                            &self.state,
                            .unlocked,
                            new_state,
                            .Acquire,
                            .Relaxed,
                        ) orelse return,
                        .locked => {},
                        .contended => break,
                    }

                    if (Futex.yield(adaptive_spin)) {
                        adaptive_spin +%= 1;
                        state = atomic.load(&self.state, .Relaxed);
                    } else {
                        break;
                    }
                }

                new_state = .contended;
                if (state != .contended) {
                    state = atomic.swap(&self.state, new_state, .Acquire);
                    if (state == .unlocked) {
                        return;
                    }
                }

                // Wait on the Lock while its contended and try to acquire it again when we wake up.
                Futex.wait(
                    @ptrCast(*const u32, &self.state),
                    @enumToInt(State.contended),
                    null,
                ) catch unreachable;
                adaptive_spin = 0;
                state = atomic.load(&self.state, .Relaxed);
            }
        }

        pub const Held = struct {
            lock: *Self,

            pub fn release(self: Held) void {
                return self.lock.release();
            }
        };

        fn release(self: *Self) void {
            switch (atomic.swap(&self.state, .unlocked, .Release)) {
                .unlocked => unreachable,
                .locked => {},
                .contended => self.releaseSlow(),
            }
        }

        fn releaseSlow(self: *Self) void {
            @setCold(true);
            Futex.wake(@ptrCast(*const u32, &self.state));
        }
    };
}

test "Lock - OS" {
    try testLock(
        Lock(@import("../parking_lot/os.zig")),
        std.Thread,
    );
}

test "Lock - Spin" {
    try testLock(
        Lock(@import("../parking_lot/spin.zig")),
        std.Thread,
    );
}

pub fn testLock(
    comptime TestLock: type,
    comptime TestThread: ?type,
) !void {
    {
        var lock = TestLock{};
        defer lock.deinit();

        var held = lock.tryAcquire() orelse unreachable;
        testing.expectEqual(lock.tryAcquire(), null);
        held.release();

        held = lock.acquire();
        defer held.release();
    }

    const Thread = TestThread orelse return;

    const Contention = struct {
        index: usize = 0,
        case: Case = undefined,
        start_event: Thread.ResetEvent = .{},
        counters: [num_counters]Counter = undefined,

        const Self = @This();
        const num_counters = 10;

        const Counter = struct {
            lock: TestLock = .{},
            remaining: u128,

            fn tryDecr(self: *Counter) bool {
                const held = self.lock.acquire();
                defer held.release();

                if (self.remaining == 0) {
                    return false;
                }

                self.remaining -= 1;
                return true;
            }
        };

        const Case = union(enum) {
            random: Random,
            high: High,
            forced: Forced,
            low: Low,

            /// The common case of many threads generally not touching other thread's Lockes
            const Low = struct {
                fn setup(_: @This(), self: *Self) void {
                    self.index = 0;
                    self.counters = [_]Counter{Counter{ .remaining = 10_000 }} ** num_counters;
                }

                fn run(_: @This(), self: *Self) void {
                    const local_index = atomic.fetchAdd(&self.index, 1, .SeqCst);
                    const local_counter = &self.counters[local_index];
                    const check_remote_every = 100;

                    var iter: usize = 0;
                    var seed: usize = undefined;
                    var prng = std.rand.DefaultPrng.init(@ptrToInt(&seed));

                    while (local_counter.tryDecr()) : (iter += 1) {
                        if (iter % check_remote_every == 0) {
                            const remote_index = prng.random.uintLessThan(usize, self.counters.len);
                            const remote_counter = &self.counters[remote_index];
                            _ = remote_counter.tryDecr();
                        }
                    }
                }
            };

            /// The extreme case of many threads fighting over the same Lock.
            const High = struct {
                fn setup(_: @This(), self: *Self) void {
                    self.counters[0] = Counter{
                        .remaining = 100_000,
                    };
                }

                fn run(_: @This(), self: *Self) void {
                    while (self.counters[0].tryDecr()) {
                        atomic.spinLoopHint();
                    }
                }
            };

            /// The slightly-less extreme case of many threads fighting over the same Lock.
            /// But they all eventually do an equal amount of work.
            const Forced = struct {
                const local_iters = 50_000;

                fn setup(_: @This(), self: *Self) void {
                    self.counters[0] = Counter{
                        .remaining = local_iters * num_counters,
                    };
                }

                fn run(_: @This(), self: *Self) void {
                    var iters: usize = local_iters;
                    while (iters > 0) : (iters -= 1) {
                        _ = self.counters[0].tryDecr();
                    }
                }
            };

            /// Stresses the common use-case of random Lock contention.
            const Random = struct {
                fn setup(_: @This(), self: *Self) void {
                    self.counters = [_]Counter{Counter{ .remaining = 10_000 }} ** num_counters;
                }

                /// Each thread iterates the counters array starting from a random position.
                /// On each iteration, it tries to lock & decrement the value of each counter is comes across.
                /// When it is unable to decrement on any counter, it terminates (seeing that they've all reached 0).
                fn run(_: @This(), self: *Self) void {
                    var seed: usize = undefined;
                    var prng = std.rand.DefaultPrng.init(@ptrToInt(&seed));

                    while (true) {
                        var did_decr = false;
                        var iter = self.counters.len;
                        var index = prng.random.int(usize) % iter;

                        while (iter > 0) : (iter -= 1) {
                            const counter = &self.counters[index];
                            index = (index + 1) % self.counters.len;
                            if (counter.tryDecr()) {
                                did_decr = true;
                            }
                        }

                        if (!did_decr) {
                            break;
                        }
                    }
                }
            };
        };

        fn run(self: *Self) void {
            self.start_event.wait();

            switch (self.case) {
                .random => |case| case.run(self),
                .high => |case| case.run(self),
                .forced => |case| case.run(self),
                .low => |case| case.run(self),
            }
        }

        fn execute(self: *Self) !void {
            const allocator = testing.allocator;
            const threads = try allocator.alloc(*Thread, num_counters);
            defer allocator.free(threads);

            defer {
                self.start_event.deinit();
                for (self.counters) |*counter| {
                    counter.lock.deinit();
                }
            }

            for ([_]Case{ .high, .random, .forced }) |contention_case| {
                self.case = contention_case;
                switch (self.case) {
                    .random => |case| case.setup(self),
                    .high => |case| case.setup(self),
                    .forced => |case| case.setup(self),
                    .low => |case| case.setup(self),
                }

                self.start_event.reset();
                for (threads) |*t| {
                    t.* = try Thread.spawn(self, Self.run);
                }

                self.start_event.set();
                for (threads) |t| {
                    t.wait();
                }

                for (self.counters) |counter| {
                    testing.expectEqual(counter.remaining, 0);
                }
            }
        }
    };

    var contention = Contention{};
    try contention.execute();
}
// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const target = std.Target.current;

const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const AtomicBitOp = enum {
    Get,
    Set,
    Reset,
    Toggle,
};

pub fn spinLoopHint() void {
    switch (target.cpu.arch) {
        .thumb, .thumbeb, .aarch64, .aarch64_be, .aarch64_32 => {
            asm volatile ("yield");
        },
        .i386, .x86_64 => {
            asm volatile ("pause");
        },
        else => {},
    }
}

test "spinLoopHint" {
    spinLoopHint();
}

pub const Ordering = enum {
    Unordered,
    Relaxed,
    Consume,
    Acquire,
    Release,
    AcqRel,
    SeqCst,

    fn toBuiltin(comptime self: Ordering) AtomicOrder {
        return switch (self) {
            .Unordered => .Unordered,
            .Relaxed => .Monotonic,
            .Consume => .Acquire, // TODO: relaxed + compilerFence(.acquire) ?
            .Acquire => .Acquire,
            .Release => .Release,
            .AcqRel => .AcqRel,
            .SeqCst => .SeqCst,
        };
    }
};

pub fn fence(comptime ordering: Ordering) void {
    switch (ordering) {
        .Acquire, .Release, .AcqRel, .SeqCst => {
            @fence(comptime ordering.toBuiltin());
        },
        else => {
            @compileLog(ordering, " only applies to a given memory location");
        },
    }
}

pub fn compilerFence(comptime ordering: Ordering) void {
    switch (ordering) {
        .SeqCst => asm volatile ("" ::: "memory"),
        .AcqRel => compilerFence(.SeqCst),
        .Acquire => compilerFence(.AcqRel),
        .Release => compilerFence(.AcqRel),
        else => @compileLog(ordering, " only applies to a given memory location"),
    }
}

test "fence/compilerFence" {
    inline for (.{ .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        compilerFence(ordering);
        fence(ordering);
    }
}

pub fn load(ptr: anytype, comptime ordering: Ordering) @TypeOf(ptr.*) {
    switch (ordering) {
        .Unordered, .Relaxed, .Consume, .Acquire, .SeqCst => {
            return @atomicLoad(@TypeOf(ptr.*), ptr, comptime ordering.toBuiltin());
        },
        .AcqRel => {
            @compileLog(ordering, " implies ", Ordering.Release, " which only applies to atomic stores");
        },
        .Release => {
            @compileLog(ordering, " only applies to atomic stores");
        },
    }
}

test "load" {
    inline for (.{ .Unordered, .Relaxed, .Consume, .Acquire, .SeqCst }) |ordering| {
        var x: usize = 5;
        testing.expectEqual(load(&x, ordering), 5);
    }
}

pub fn store(ptr: anytype, value: @TypeOf(ptr.*), comptime ordering: Ordering) void {
    switch (ordering) {
        .Unordered, .Relaxed, .Release, .SeqCst => {
            return @atomicLoad(@TypeOf(ptr.*), ptr, comptime ordering.toBuiltin());
        },
        .AcqRel => {
            @compileLog(ordering, " implies ", Ordering.Acquire, " which only applies to atomic loads");
        },
        .Acquire, .Consume => {
            @compileLog(ordering, " only applies to atomic loads");
        },
    }
}

test "store" {
    inline for (.{ .Unordered, .Relaxed, .Release, .SeqCst }) |ordering| {
        var x: usize = 5;
        store(&x, 10, ordering);
        testing.expectEqual(load(&x, .SeqCst), 10);
    }
}

pub fn swap(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Xchg, value, ordering);
}

test "swap" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 5;
        testing.expectEqual(swap(&x, 10, ordering), 5);
        testing.expectEqual(load(&x, .SeqCst), 10);

        var y: enum(usize) { a, b, c } = .c;
        testing.expectEqual(swap(&y, .a, ordering), .c);
        testing.expectEqual(load(&y, .SeqCst), .c);

        var z: f32 = 5.0;
        testing.expectEqual(swap(&z, 10.0, ordering), 5.0);
        testing.expectEqual(load(&z, .SeqCst), 10.0);

        var a: bool = false;
        testing.expectEqual(swap(&a, true, ordering), false);
        testing.expectEqual(load(&a, .SeqCst), false);

        var b: ?*u8 = null;
        testing.expectEqual(swap(&b, @intToPtr(?*u8, @alignOf(u8)), ordering), null);
        testing.expectEqual(load(&b, .SeqCst), @intToPtr(?*u8, @alignOf(u8)));
    }
}

pub fn fetchAdd(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Add, value, ordering);
}

test "fetchAdd" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 5;
        testing.expectEqual(fetchAdd(&x, 5, ordering), 5);
        testing.expectEqual(load(&x, .SeqCst), 10);
    }
}

pub fn fetchSub(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Sub, value, ordering);
}

test "fetchSub" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 5;
        testing.expectEqual(fetchSub(&x, 5, ordering), 5);
        testing.expectEqual(load(&x, .SeqCst), 0);
    }
}

pub fn fetchAnd(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .And, value, ordering);
}

test "fetchAnd" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0b11;
        testing.expectEqual(fetchAnd(&x, 0b10, ordering), 0b11);
        testing.expectEqual(load(&x, .SeqCst), 0b10);
        testing.expectEqual(fetchAnd(&x, 0b00, ordering), 0b10);
        testing.expectEqual(load(&x, .SeqCst), 0b00);
    }
}

pub fn fetchOr(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Or, value, ordering);
}

test "fetchOr" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0b11;
        testing.expectEqual(fetchOr(&x, 0b100, ordering), 0b11);
        testing.expectEqual(load(&x, .SeqCst), 0b111);
        testing.expectEqual(fetchOr(&x, 0b010, ordering), 0b111);
        testing.expectEqual(load(&x, .SeqCst), 0b111);
    }
}

pub fn fetchXor(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Xor, value, ordering);
}

test "fetchXor" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0b11;
        testing.expectEqual(fetchXor(&x, 0b10, ordering), 0b11);
        testing.expectEqual(load(&x, .SeqCst), 0b01);
        testing.expectEqual(fetchXor(&x, 0b01, ordering), 0b01);
        testing.expectEqual(load(&x, .SeqCst), 0b00);
    }
}

fn atomicRmw(
    comptime T: type,
    ptr: anytype,
    comptime op: AtomicRmwOp,
    value: T,
    comptime ordering: Ordering,
) callconv(.Inline) T {
    @setRuntimeSafety(false);

    switch (ordering) {
        .SeqCst, .AcqRel, .Acquire, .Release, .Consume, .Relaxed => {},
        .Unordered => {
            @compileLog(ordering, " only applies to atomic loads or stores, not read-modify-write operations");
        },
    }
    
    // TODO: https://github.com/ziglang/zig/issues/8597
    switch (target.cpu.arch) {
        .arm, .armeb, .thumb, .thumbeb, .aarch64, .aarch64_be, .aarch64_32 => {},
        else => {
            return @atomicRmw(T, ptr, op, value, comptime ordering.toBuiltin());
        },
    }

    const AtomicRmwHelper = struct {
        fn unsafeCast(comptime U: type, current: anytype) U {
            var fill: U = undefined;
            @memcpy(@ptrCast([*]u8, &fill), @ptrCast([*]const u8, &current), @sizeOf(U));
            return fill;
        }

        fn bitCountOf(comptime U: type) ?u16 {
            return switch (@typeInfo(U)) {
                .Bool => @sizeOf(bool) * 8,
                .Int => |info| blk: {
                    if (info.bits % 8 != 0) break :blk null;
                    break blk: info.bits,
                },
                .Float => |info| blk: {
                    if (info.bits % 8 != 0) break :blk null;
                    break blk: info.bits,
                },
                .Enum => |info| bitCountOf(info.tag_type),
                .Optional => |info| switch (@typeInfo(info.child)) {
                    .Pointer => bitCountOf(info.child),
                    else => null,
                },
                .Pointer => |info| blk: {
                    if (info.is_const or info.is_volatile) break :blk null;
                    if (info.size == .Slice) break :blk null;
                    break :blk bitCountOf(usize);
                },
                else => null,
            };
        }
    };

    const bit_count = AtomicRmwHelper.bitCountOf(T) orelse {
        @compileError(@typeName(T) ++ " does not support atomic operations");
    };

    const Int = std.meta.Int(.unsigned, bit_count);
    const int_ptr = @intToPtr(*Int, @ptrToInt(ptr));

    var old_int = @atomicLoad(Int, int_ptr, .Monotonic);
    while (true) {
        const old_value = AtomicRmwHelper.unsafeCast(T, old_int);
        const new_value = switch (op) {
            .Xchg => value,
            .Add => old_value + value,
            .Sub => old_value - value,
            .And => old_value & value,
            .Or => old_value | value,
            .Xor => old_value ^ value,
            else => @compileLog(op, " unimplemented"),
        };

        const new_int = AtomicRmwHelper.unsafeCast(Int, new);
        old_int = @cmpxchgWeak(
            Int, 
            int_ptr, 
            old_int, 
            new_int, 
            ordering, 
            .Monotonic,
        ) orelse return old_value; 
    }
}

pub fn compareAndSwap(
    ptr: anytype,
    compare: @TypeOf(ptr.*),
    exchange: @TypeOf(ptr.*),
    comptime success: Ordering,
    comptime failure: Ordering,
) ?@TypeOf(ptr.*) {
    return cmpxchg(true, @TypeOf(ptr.*), ptr, compare, exchange, success, failure);
}

pub fn tryCompareAndSwap(
    ptr: anytype,
    compare: @TypeOf(ptr.*),
    exchange: @TypeOf(ptr.*),
    comptime success: Ordering,
    comptime failure: Ordering,
) ?@TypeOf(ptr.*) {
    return cmpxchg(false, @TypeOf(ptr.*), ptr, compare, exchange, success, failure);
}

fn cmpxchg(
    comptime is_strong: bool,
    comptime T: type,
    ptr: *T,
    compare: T,
    exchange: T,
    comptime success: Ordering,
    comptime failure: Ordering,
) callconv(.Inline) ?T {
    switch (failure) {
        .SeqCst => {},
        .AcqRel => {
            @compileLog("Failure ordering ", failure, " implies ", Ordering.Release, " which only applies to atomic stores, not the atomic load on failed comparison");
        },
        .Acquire => {},
        .Release => {
            @compileLog("Failure ordering ", failure, " only applies to atomic stores, not the atomic load on failed comparison");
        },
        .Relaxed => {},
        .Consume, .Unordered => {
            @compileLog("Failure ordering ", failure, " only applies to atomic loads or stores, not read-modify-write operations");
        },
    }

    const is_stronger = switch (success) {
        .SeqCst => true,
        .AcqRel, .Acquire, .Release => failure == .Acquire or failure == .Relaxed,
        .Relaxed => failure == .Relaxed,
        .Consume, .Unordered => {
            @compileLog("Success ordering ", success, " only applies to atomic loads or stores, not read-modify-write operations");
        },
    };

    if (!is_stronger) {
        @compileLog("Success ordering ", success, " is weaker than failure ordering ", failure);
    }

    const succ = comptime success.toBuiltin();
    const fail = comptime failure.toBuiltin();
    return switch (is_strong) {
        true => @cmpxchgStrong(T, ptr, compare, exchange, succ, fail),
        else => @cmpxchgWeak(T, ptr, compare, exchange, succ, fail),
    };
}

const CMPXCHG_ORDERINGS = .{
    .{ .Relaxed, .Relaxed },
    .{ .Consume, .Relaxed },
    .{ .Consume, .Consume },
    .{ .Acquire, .Relaxed },
    .{ .Acquire, .Consume },
    .{ .Acquire, .Acquire },
    .{ .Release, .Relaxed },
    .{ .Release, .Consume },
    .{ .Release, .Acquire },
    .{ .AcqRel, .Relaxed },
    .{ .AcqRel, .Consume },
    .{ .AcqRel, .Acquire },
    .{ .SeqCst, .Relaxed },
    .{ .SeqCst, .Consume },
    .{ .SeqCst, .Acquire },
    .{ .SeqCst, .SeqCst },
};

test "compareAndSwap" {
    inline for (CMPXCHG_ORDERINGS) |ordering| {
        var x: usize = 0;
        testing.expectEqual(compareAndSwap(&x, 1, 0, ordering[0], ordering[1]), 0);
        testing.expectEqual(load(&x, .SeqCst), 0);
        testing.expectEqual(compareAndSwap(&x, 0, 1, ordering[0], ordering[1]), null);
        testing.expectEqual(load(&x, .SeqCst), 1);
        testing.expectEqual(compareAndSwap(&x, 1, 0, ordering[0], ordering[1]), null);
        testing.expectEqual(load(&x, .SeqCst), 0);
    }
}

test "tryCompareAndSwap" {
    inline for (CMPXCHG_ORDERINGS) |ordering| {
        var x: usize = 0;
        var c = load(&x, ordering[1]);

        // update x from 0 to 1 in a loop in order to account for spurious failures
        while (true) {
            testing.expectEqual(c, x);
            testing.expectEqual(c, 0);
            c = tryCompareAndSwap(&x, c, 1, ordering[0], ordering[1]) orelse break;
        }

        testing.expectEqual(c, 0);
        testing.expectEqual(load(&x, ordering[1]), 1);
    }
}

pub fn bitGet(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Get, bit, ordering);
}

test "bitGet" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .SeqCst }) |ordering| {
        for ([_]usize{ 0b00, 0b01, 0b10, 0b11 }) |value| {
            var x: usize = value;
            testing.expectEqual(bitGet(&x, 0, ordering), @boolToInt(value & (1 << 0) != 0));
            testing.expectEqual(bitGet(&x, 1, ordering), @boolToInt(value & (1 << 1) != 0));
        }
    }
}

pub fn bitSet(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Set, bit, ordering);
}

test "bitSet" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0;
        const bit_array = @as([std.meta.bitCount(usize)]void, undefined);

        for (bit_array) |_, bit_index| {
            const bit = @intCast(std.meta.Log2Int(usize), bit_index);
            const mask = @as(usize, 1) << bit;

            // setting the bit should change the bit
            testing.expect(load(&x, .SeqCst) & mask == 0);
            testing.expectEqual(bitSet(&x, bit, ordering), 0);
            testing.expect(load(&x, .SeqCst) & mask != 0);

            // setting it again shouldn't change the value
            testing.expectEqual(bitSet(&x, bit, ordering), 1);
            testing.expect(load(&x, .SeqCst) & mask != 0);

            // all the previous bits should have not changed (still be set)
            for (bit_array[0..bit_index]) |_, prev_bit_index| {
                const prev_bit = @intCast(std.meta.Log2Int(usize), prev_bit_index);
                const prev_mask = @as(usize, 1) << prev_bit;
                testing.expect(load(&x, .SeqCst) & prev_mask != 0);
            }
        }
    }
}

pub fn bitReset(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Reset, bit, ordering);
}

test "bitReset" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0;
        const bit_array = @as([std.meta.bitCount(usize)]void, undefined);

        for (bit_array) |_, bit_index| {
            const bit = @intCast(std.meta.Log2Int(usize), bit_index);
            const mask = @as(usize, 1) << bit;
            x |= mask;

            // unsetting the bit should change the bit
            testing.expect(load(&x, .SeqCst) & mask != 0);
            testing.expectEqual(bitReset(&x, bit, ordering), 1);
            testing.expect(load(&x, .SeqCst) & mask == 0);

            // unsetting it again shouldn't change the value
            testing.expectEqual(bitReset(&x, bit, ordering), 0);
            testing.expect(load(&x, .SeqCst) & mask == 0);

            // all the previous bits should have not changed (still be reset)
            for (bit_array[0..bit_index]) |_, prev_bit_index| {
                const prev_bit = @intCast(std.meta.Log2Int(usize), prev_bit_index);
                const prev_mask = @as(usize, 1) << prev_bit;
                testing.expect(load(&x, .SeqCst) & prev_mask == 0);
            }
        }
    }
}

pub fn bitToggle(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Toggle, bit, ordering);
}

test "bitToggle" {
    inline for (.{ .Relaxed, .Consume, .Acquire, .Release, .AcqRel, .SeqCst }) |ordering| {
        var x: usize = 0;
        const bit_array = @as([std.meta.bitCount(usize)]void, undefined);

        for (bit_array) |_, bit_index| {
            const bit = @intCast(std.meta.Log2Int(usize), bit_index);
            const mask = @as(usize, 1) << bit;

            // toggling the bit should change the bit
            testing.expect(load(&x, .SeqCst) & mask == 0);
            testing.expectEqual(bitToggle(&x, bit, ordering), 0);
            testing.expect(load(&x, .SeqCst) & mask != 0);

            // toggling it again *should* change the value
            testing.expectEqual(bitToggle(&x, bit, ordering), 1);
            testing.expect(load(&x, .SeqCst) & mask == 0);

            // all the previous bits should have not changed (still be toggled back)
            for (bit_array[0..bit_index]) |_, prev_bit_index| {
                const prev_bit = @intCast(std.meta.Log2Int(usize), prev_bit_index);
                const prev_mask = @as(usize, 1) << prev_bit;
                testing.expect(load(&x, .SeqCst) & prev_mask == 0);
            }
        }
    }
}

fn atomicBit(
    comptime T: type, 
    ptr: *T, 
    comptime op: AtomicBitOp, 
    bit: std.meta.Log2Int(T), 
    comptime ordering: Ordering,
) u1 {
    const mask = @as(T, 1) << bit;
    const bytes = @sizeOf(T);
    const is_x86 = switch (target.cpu.arch) {
        .i386, .x86_64 => true,
        else => false,
    };

    if (is_x86 and bytes <= @sizeOf(usize) and op != .Get) {
        const instruction: []const u8 = switch (op) {
            .Get => unreachable,
            .Set => "lock bts",
            .Reset => "lock btr",
            .Toggle => "lock btc",
        };

        const suffix: []const u8 = switch (bytes) {
            // on x86, faults are by page. If at least one byte is valid, the operation will succeed.
            1, 2 => "w",
            4 => "l",
            8 => "q",
            else => unreachable,
        };

        // Use the largest priitive chosen above
        const Bit = std.meta.Int(
            .unsigned, 
            std.math.max(2, bytes) * 8,
        );

        return @intCast(u1, asm volatile (instruction ++ suffix ++ " %[bit], %[ptr]"
            : [result] "={@ccc}" (-> u8)
            : [ptr] "*p" (ptr),
              [bit] "X" (@as(Bit, bit))
            : "cc", "memory"
        ));
    }

    const value = blk: {
        if (op == .Get) {
            break :blk load(ptr, ordering);
        }

        if (target.cpu.arch.isRISCV()) {
            break :blk switch (op) {
                .Get => unreachable,
                .Set => fetchOr(ptr, mask, ordering),
                .Reset => fetchAnd(ptr, ~mask, ordering),
                .Toggle => fetchXor(ptr, mask, ordering),
            };
        };

        const success = ordering;
        const failure = switch (ordering) {
            .SeqCst => .SeqCst,
            .AcqRel, .Acquire, .Consume => .Acquire,
            .Release, .Relaxed => .Relaxed,
            .Unordered => {
                @compileLog(ordering, " only applies to atomic loads or stores, not read-modify-write operations");
            },
        };

        var old = @atomicLoad(T, ptr, failure);
        while (true) {
            const new = switch (op) {
                .Get => unreachable,
                .Set => value | mask,
                .Reset => value & ~mask,
                .Toggle => value ^ mask,
            };
            
            if (old == new) break :blk old;
            old = @cmpxchgWeak(
                T,
                ptr,
                old,
                new,
                comptime success.toBuiltin(),
                comptime failure.toBuiltin(),
            ) orelse break :blk old;
        }
    };

    return @boolToInt(value & mask != 0);
}

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

pub fn swap(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Xchg, value, ordering);
}

pub fn fetchAdd(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Add, value, ordering);
}

pub fn fetchSub(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Sub, value, ordering);
}

pub fn fetchAnd(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .And, value, ordering);
}

pub fn fetchOr(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Or, value, ordering);
}

pub fn fetchXor(
    ptr: anytype,
    value: @TypeOf(ptr.*),
    comptime ordering: Ordering,
) @TypeOf(ptr.*) {
    return atomicRmw(@TypeOf(ptr.*), ptr, .Xor, value, ordering);
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

pub fn bitGet(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Get, bit, ordering);
}

pub fn bitSet(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Set, bit, ordering);
}

pub fn bitReset(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Reset, bit, ordering);
}

pub fn bitToggle(
    ptr: anytype, 
    bit: std.meta.Log2Int(@TypeOf(ptr.*)), 
    comptime ordering: Ordering,
) u1 {
    return atomicBit(@TypeOf(ptr.*), ptr, .Toggle, bit, ordering);
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

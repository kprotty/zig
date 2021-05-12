// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! An Duration is a unit of time used for type-safe time-related APIs.

const std = @import("../../std.zig");
const Duration = @This();

nanoseconds: u64,

pub fn fromNanos(ns: u64) Duration {
    return .{ .nanoseconds = ns };
}

pub fn fromMicros(us: u64) Duration {
    return .{ .nanoseconds = us * std.time.ns_per_us };
}

pub fn fromMillis(ms: u64) Duration {
    return .{ .nanoseconds = ms * std.time.ns_per_ms };
}

pub fn fromSecs(secs: u64) Duration {
    return .{ .nanoseconds = secs * std.time.ns_per_s };
}

pub fn toNanos(self: Duration) u64 {
    return self.nanoseconds;
}

pub fn toMicros(self: Duration) u64 {
    return self.nanoseconds / std.time.ns_per_us;
}

pub fn toMillis(self: Duration) u64 {
    return self.nanoseconds / std.time.ns_per_ms; 
}

pub fn toSecs(self: Duration) u32 {
    return self.nanoseconds / std.time.ns_per_s;
}

pub fn format(
    self: Duration,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    out_stream: anytype,
) !void {
    if (self.nanoseconds >= std.time.ns_per_hour) {
        const hours = self.nanoseconds / std.time.ns_per_hour;
        const mins = (self.nanoseconds % std.time.ns_per_hour) / std.time.ns_per_min;
        const secs = (self.nanoseconds % std.time.ns_per_min) / std.time.ns_per_s;
        return std.fmt.format(out_stream, "{d:0>2}:{d:0>2}:{d:0>2}", .{hours, mins, secs});
    }

    if (self.nanoseconds >= std.time.ns_per_min) {
        const mins = self.nanoseconds / std.time.ns_per_min;
        const secs = (self.nanoseconds % std.time.ns_per_min) / std.time.ns_per_s;
        if (secs == 0) {
            return std.fmt.format(out_stream, "{}m", .{mins});
        } else {
            return std.fmt.format(out_stream, "{}m{}s", .{mins, secs});
        }
    }

    if (self.nanoseconds >= std.time.ns_per_s) {
        const ms = @intToFloat(f64, self.toMillis());
        return std.fmt.format(out_stream, "{d:.2}s", .{ms / std.time.ms_per_s});
    }
    
    if (self.nanoseconds >= std.time.ns_per_ms) {
        return std.fmt.format(out_stream, "{}ms", .{self.toMillis()});
    }
    
    if (self.nanoseconds >= std.time.ns_per_us) {
        return std.fmt.format(out_stream, "{}μs", .{self.toMicros()});
    }
    
    return std.fmt.format(out_stream, "{}ns", .{self.nanoseconds});
}
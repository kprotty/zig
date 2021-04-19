// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const target = std.Target.current;
const Instant = @This();

timestamp: u64,

pub fn now() Instant {
    return .{ .timestamp = CpuClock.read() orelse OsClock.read() };
}

pub fn since(self: Instant, earlier: Instant) ?u64 {
    var delta: u64 = undefined;
    if (@subWithOverflow(u64, self.timestamp, earlier.timestamp, &delta)) {
        return null;
    }

    if (delta == 0) return 0;
    return CpuClock.toDuration(delta) orelse OsClock.toDuration(delta);
}

const CpuClock = switch (target.cpu.arch) {
    .x86_64 => Intel64Clock,
    else => struct {
        pub fn read() ?u64 {
            return null;
        }

        pub fn toDuration(delta: u64) ?u64 {
            return null;
        }
    },
};

const Intel64Clock = struct {
    var tsc_status = Status.Uninit;
    var tsc_scale: u64 = 0;

    const Status = enum(u8) {
        Uninit,
        Supported,
        Unsupported,
    };

    pub fn read() ?u64 {
        return switch (@atomicLoad(Status, &tsc_status, .Acquire)) {
            .Uninit => readSlow(),
            .Unsupported => null,
            .Supported => rdtscp(),
        };
    }

    fn readSlow() ?u64 {
        @setCold(true);

        const extensions = asm (
            \\ cpuid
            : [ext] "={eax}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000000))
        );

        const has_rdtscp = (extensions >= 0x80000001) and asm (
            \\ cpuid
            : [ext] "={edx}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000001))
        ) & (1 << 27) != 0;

        const has_invariant_tsc = has_rdtscp and (extensions >= 0x80000007) and asm (
            \\ cpuid
            : [ext] "={edx}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000007))
        ) & (1 << 8) != 0;

        if (!has_invariant_tsc) {
            @atomicStore(Status, &tsc_status, .Unsupported, .Monotonic);
            return null;
        }

        const scale = blk: {
            var os_time: [2]u64 = undefined;
            var cpu_time: [2]u64 = undefined;

            os_time[0] = OsClock.read();
            cpu_time[0] = rdtscp();

            while (true) {
                cpu_time[1] = rdtscp();
                os_time[1] = OsClock.read();
                if (cpu_time[1] < cpu_time[0]) continue;
                if (os_time[1] < os_time[0]) continue;
                break;
            }

            const elapsed = @intToFloat(f64, OsClock.toDuration(os_time[1] - os_time[0]));
            const cpu_per_ns = @intToFloat(f64, cpu_time[1] - cpu_time[0]) / elapsed;
            break :blk @bitCast(u64, cpu_per_ns);
        };

        _ = @cmpxchgStrong(
            u64,
            &tsc_scale,
            @as(u64, 0),
            scale,
            .Monotonic,
            .Monotonic,
        );

        @atomicStore(Status, &tsc_status, .Supported, .Release);
        return rdtscp();
    }

    pub fn toDuration(delta: u64) ?u64 {
        switch (@atomicLoad(Status, &tsc_status, .Acquire)) {
            .Uninit => unreachable,
            .Unsupported => null,
            .Supported => {
                const ticks_per_ns = @bitCast(f64, tsc_scale);
                const elapsed = @intToFloat(f64, delta) / ticks_per_ns;
                return @floatToInt(u64, elapsed);
            },
        }
    }

    fn rdtscp() callconv(.Inline) u64 {
        return asm volatile (
            \\ rdtscp
            \\ shl $32, %%rdx
            \\ or %%rdx, %%rax
            : [ret] "={rax}" (-> u64)
            :
            : "eax", "edx", "ecx", "memory"
        );
    }
};

const OsClock = if (target.isWindows())
    WindowsClock
else if (target.isDarwin())
    DarwinClock
else if (target.isLinux() or std.builtin.link_libc)
    PosixClock
else if (target.os.tag == .wasi)
    WasiClock
else
    @compileError("OsClock source not detected");

const PosixClock = struct {
    fn read() u64 {
        var ts: std.os.timespec = undefined;
        std.os.clock_gettime(std.os.CLOCK_MONOTONIC, &ts) catch return 0;
        return (@intCast(u64, ts.tv_sec) * std.time.ns_per_s) + @intCast(u64, ts.tv_nsec);
    }

    fn toDuration(delta: u64) u64 {
        return delta;
    }
};

const WasiClock = struct {
    fn read() u64 {
        var timestamp: std.os.wasi.timestamp_t = undefined;
        const status = std.os.wasi.clock_time_get(std.os.wasi.CLOCK_MONOTONIC, 1, &timestamp);
        if (status != std.os.wasi.ESUCCESS) return 0;
        return timestamp;
    }

    fn toDuration(delta: u64) u64 {
        return delta;
    }
};

const DarwinClock = struct {
    fn read() u64 {
        return std.os.darwin.mach_absolute_time();
    }

    var info = std.mem.zeroes(std.os.darwin.mach_timebase_info_data);

    fn toDuration(delta: u64) u64 {
        if (@atomicLoad(u32, &info.numer, .Unordered) == 0) {
            const status = std.os.darwin.mach_timebase_info(&info);
            if (status != std.os.darwin.KERN_SUCCESS) {
                return 0;
            }
        }

        var duration = delta;
        if (info.numer > 1) duration *= info.numer;
        if (info.denom > 1) duration /= info.denom;
        return duration;
    }
};

const WindowsClock = struct {
    fn read() u64 {
        return std.os.windows.QueryPerformanceCounter();
    }

    fn toDuration(delta: u64) u64 {
        var duration: u128 = delta;
        duration *= std.time.ns_per_s;
        duration /= getFrequency();
        return std.math.cast(u64, duration) catch std.math.maxInt(u64);
    }

    fn getFrequency() callconv(.Inline) u64 {
        return (switch (target.cpu.arch) {
            .x86_64, .aarch64 => struct {
                var frequency: u64 = 0;

                fn get() callconv(.Inline) u64 {
                    return switch (@atomicLoad(u64, &frequency, .Unordered)) {
                        0 => getSlow(),
                        else => |f| f,
                    };
                }

                fn getSlow() u64 {
                    @setCold(true);
                    const f = std.os.QueryPerformanceFrequency();
                    @atomicStore(u64, &frequency, f, .Unordered);
                    return f;
                }
            },
            else => struct {
                threadlocal var tls_frequency: u64 = 0;

                fn get() callconv(.Inline) u64 {
                    return switch (tls_frequency) {
                        0 => getSlow(),
                        else => |f| f,
                    };
                }

                fn getSlow() u64 {
                    @setCold(true);
                    const f = std.os.QueryPerformanceFrequency();
                    tls_frequency = f;
                    return f;
                }
            },
        }).get();
    }
};

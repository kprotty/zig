// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! An Instant represents a moment in time as recorded by the OS.
//!
//! Ideally, Instant snapshots are monotonically increasing but not steady.
//! Meaning that it shouldn't appear go backwards, but it *can* appear to 
//! speed up, slow down, or stand still and not progress at all.
//!
//! `now` can be used to take a snapshot and `since` can be used to check
//! for wall-clock time elapsed, and transitively, for the monotonici property.

const std = @import("../std.zig");
const target = std.Target.current;
const Instant = @This();

timestamp: u64,

/// Take a snapshot of the current timestamp, recorded as an Instant.
///
/// Instants can be compared with other to get wall-clock time passed
/// but are otherwise opaque in their representation.
pub fn now() Instant {
    return .{ .timestamp = CpuClock.read() orelse OsClock.read() };
}

/// Return the amount of nanoseconds in wall-clock time that have elapsed
/// since the given `earlier` Instant. If the `earlier` Instant was actually 
/// "later" than the `self` Instant, null is returned.
pub fn since(self: Instant, earlier: Instant) ?u64 {
    var delta: u64 = undefined;
    if (@subWithOverflow(u64, self.timestamp, earlier.timestamp, &delta)) {
        return null;
    }

    if (delta == 0) return 0;
    return CpuClock.getElapsed(delta) orelse OsClock.getElapsed(delta);
}

/// An Instant clock source which uses the CPU.
/// When available, this is preferred over `OsClock` due to potentially faster sampling.
const CpuClock = switch (target.cpu.arch) {
    .x86_64 => Intel64Clock,
    else => struct {
        pub fn read() ?u64 {
            return null;
        }

        pub fn getElapsed(delta: u64) ?u64 {
            return null;
        }
    },
};

/// CpuClock implementation for x86_64 CPUs
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

        // Get the max extensions value for cpuid
        const extensions = asm (
            \\ cpuid
            : [ext] "={eax}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000000))
        );

        // Check if the current cpu supports the rdtscp instruction.
        // If not, we could default to `lfence; rdtsc` for Intel/AMD cpus,
        // but supporting such older CPUS is not worth it at the moment.
        const has_rdtscp = (extensions >= 0x80000001) and asm (
            \\ cpuid
            : [ext] "={edx}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000001))
        ) & (1 << 27) != 0;

        // Also check if the current CPU supports invariant TSC.
        // This means that the cycles reported by `rdtscp` advances at a constant rate
        // and that it does so in various processor states (e.g. suspend/pause/etc.).
        // This is also the requirement for `rdtsc` usage imposed by the Tracy Profiler.
        const has_invariant_tsc = (extensions >= 0x80000007) and asm (
            \\ cpuid
            : [ext] "={edx}" (-> u32)
            : [leaf] "{eax}" (@as(u32, 0x80000007))
        ) & (1 << 8) != 0;

        if (!has_rdtscp or !has_invariant_tsc) {
            @atomicStore(Status, &tsc_status, .Unsupported, .Monotonic);
            return null;
        }

        // Try to figure out the rate of cycles reported by rdtscp() / nanosecond
        const scale = blk: {
            var os_time: [2]u64 = undefined;
            var cpu_time: [2]u64 = undefined;

            os_time[0] = OsClock.read();
            cpu_time[0] = rdtscp();

            // Spin for a few cycles to get more accurate measurement
            const max_spin = 5 * std.time.ns_per_us;
            while (true) {
                std.os.sched_yield() catch {};
                const os_now = OsClock.read();
                if (os_now < os_time[0]) continue;
                if (os_now - os_time[0] < max_spin) continue;
                break;
            }

            // Get the elapsed time by recording both cpu & os time, retrying if they go backwards.
            while (true) {
                cpu_time[1] = rdtscp();
                os_time[1] = OsClock.read();
                if (cpu_time[1] < cpu_time[0]) continue;
                if (os_time[1] < os_time[0]) continue;
                break;
            }

            // Compute the amount of "cycles per nanosecond" as a float and store the bits as a u64.
            const elapsed = @intToFloat(f64, OsClock.getElapsed(os_time[1] - os_time[0]));
            const cpu_per_ns = @intToFloat(f64, cpu_time[1] - cpu_time[0]) / elapsed;
            break :blk @bitCast(u64, cpu_per_ns);
        };
        
        // Racily update the scale for which ever thread computes it the fastest.
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

    pub fn getElapsed(delta: u64) ?u64 {
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

    fn getElapsed(delta: u64) u64 {
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

    fn getElapsed(delta: u64) u64 {
        return delta;
    }
};

const DarwinClock = struct {
    fn read() u64 {
        return std.os.darwin.mach_absolute_time();
    }

    var info = std.mem.zeroes(std.os.darwin.mach_timebase_info_data);

    fn getElapsed(delta: u64) u64 {
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

    fn getElapsed(delta: u64) u64 {
        var duration: u128 = delta;
        duration *= std.time.ns_per_s;
        duration /= getFrequency();
        return std.math.cast(u64, duration) catch std.math.maxInt(u64);
    }

    fn getFrequency() callconv(.Inline) u64 {
        // Get the performance frequency by caching it either
        // globally if 64bit atomics are available or thread local if otherwise.
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

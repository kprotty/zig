// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

pub const core = importAll("");
pub const serial = importAll("Serial");

fn importAll(comptime prefix: []const u8) type {
    return struct {
        pub const Mutex = importPrimitive("Mutex");
        pub const ParkingLot = importPrimitive("ParkingLot");
        
        fn importPrimitive(comptime primitive: []const u8) type {
            const module = @import("./primitives/" ++ primitive ++ ".zig");
            return @field(module, prefix ++ primitive);
        }
    };
}

pub const os = with(@import("./parking_lot/os.zig"));
pub const spin = with(@import("./parking_lot/spin.zig"));
pub const event = with(@import("./parking_lot/event.zig"));

pub fn with(comptime parking_lot_backend: type) type {
    return struct {
        pub const parking_lot = parking_lot_backend;
        
        pub const Mutex = core.Mutex(parking_lot);
    };
}


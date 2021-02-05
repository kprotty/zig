// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const _mutex = @import("./primitives/Mutex.zig");
const _once = @import("./primitives/Once.zig");
const _parking_lot = @import("./primitives/ParkingLot.zig");
const _reset_event = @import("./primitives/ResetEvent.zig");

pub const core = struct {
    pub const Mutex = _mutex.Mutex;
    pub const Once = _once.Once;
    pub const ParkingLot = _parking_lot.ParkingLot;
    pub const ResetEvent = _reset_event.ResetEvent;
};

pub const serial = struct {
    pub const Mutex = _mutex.SerialMutex;
    pub const Once = _once.SerialOnce;
    pub const ParkingLot = _parking_lot.SerialParkingLot;
    pub const ResetEvent = _reset_event.SerialResetEvent;
};

pub const os = with(@import("./parking_lot/os.zig"));
pub const spin = with(@import("./parking_lot/spin.zig"));
pub const event = with(@import("./parking_lot/event.zig"));

pub fn with(comptime parking_lot_backend: type) type {
    return struct {
        pub const parking_lot = parking_lot_backend;
        
        pub const Mutex = core.Mutex(parking_lot);
        pub const Once = core.Once(parking_lot);
        pub const ResetEvent = core.ResetEvent(parking_lot);
    };
}

test "" {
    _ = _mutex;
    _ = _once;
    _ = _parking_lot;
    _ = _reset_event;
}

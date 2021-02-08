// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const lock_impl = @import("./primitives/Lock.zig");
const mutex_impl = @import("./primitives/Mutex.zig");
const once_impl = @import("./primitives/Once.zig");
const reset_event_impl = @import("./primitives/ResetEvent.zig");

const parking_lot_impl = @import("./parking_lot/ParkingLot.zig");
const parking_lot_os = @import("./parking_lot/os.zig");
const parking_lot_spin = @import("./parking_lot/spin.zig");
const parking_lot_event = @import("./parking_lot/event.zig");

pub const core = struct {
    pub const Futex = futex_impl.Futex;
    pub const Lock = lock_impl.Lock;
    pub const Mutex = mutex_impl.Mutex;
    pub const Once = once_impl.Once;
    pub const ResetEvent = reset_event_impl.ResetEvent;
};

pub const serial = struct {
    pub const parking_lot = parking_lot_impl.SerialParkingLot;

    pub const Futex = futex_impl.SerialFutex;
    pub const Lock = lock_impl.SerialLock;
    pub const Mutex = mutex_impl.SerialMutex;
    pub const Once = once_impl.SerialOnce;
    pub const ResetEvent = reset_event_impl.SerialResetEvent;
};

pub const os = with(parking_lot_os);
pub const spin = with(parking_lot_spin);
pub const event = with(parking_lot_event);

pub fn with(comptime parking_lot_backend: type) type {
    return struct {
        pub const parking_lot = parking_lot_backend;
        
        pub const Futex = core.Futex(parking_lot);
        pub const Lock = core.Lock(parking_lot);
        pub const Mutex = core.Mutex(parking_lot);
        pub const Once = core.Once(parking_lot);
        pub const ResetEvent = core.ResetEvent(parking_lot);
    };
}

test "" {
    _ = parking_lot_impl;
    _ = lock_impl;
    _ = mutex_impl;
    _ = once_impl;
    _ = reset_event_impl;
}

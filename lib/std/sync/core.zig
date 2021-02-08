// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const futex_impl = @import("./core/Futex.zig");
const lock_impl = @import("./core/Lock.zig");
const mutex_impl = @import("./core/Mutex.zig");
const once_impl = @import("./core/Once.zig");
const parking_lot_impl = @import("./core/ParkingLot.zig");
const reset_event_impl = @import("./core/ResetEvent.zig");

pub fn with(comptime backend: type) type {
    return struct {
        pub const parking_lot = parking_lot_impl.ParkingLot(backend);

        pub const Futex = futex_impl.Futex(parking_lot);
        pub const Lock = lock_impl.Lock(parking_lot);
        pub const Mutex = mutex_impl.Mutex(parking_lot);
        pub const Once = once_impl.Once(parking_lot);
        pub const ResetEvent = reset_event_impl.ResetEvent(parking_lot);
    };
}

test "" {
    _ = @import("./core/generic/EventLock.zig");
    _ = @import("./core/generic/FutexEvent.zig");
    _ = @import("./core/generic/FutexLock.zig");

    _ = futex_impl;
    _ = lock_impl;
    _ = mutex_impl;
    _ = once_impl;
    _ = parking_lot_impl;
    _ = reset_event_impl;
}
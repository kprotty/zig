// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

/// A ParkingLot configuration which blocks by calling into the OS.
pub const os = @import("./backend/os.zig");

/// A ParkingLot configuration which blocks by spinning atomically.
pub const spin = @import("./backend/spin.zig");

/// A ParkingLot configuration which blocks using the std.event.Loop.
pub const event = @import("./backend/event.zig");

/// A ParkingLot configuration which is optimized for std.builtin.single_threaded and panics if blocked.
pub const serial = @import("./backend/serial.zig");
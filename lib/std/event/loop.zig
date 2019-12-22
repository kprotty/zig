const std = @import("../std.zig");
const builtin = @import("builtin");
const root = @import("root");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

usingnamespace switch (builtin.os) {
    .windows => @import("reactor/windows.zig"),
    .linux => @import("reactor/linux.zig"),
    else => @import("reactor/posix.zig"),
};

/// Parallel, work-stealing event loop implementation influenced by the golang scheduler:
/// https://github.com/golang/go/blob/master/src/runtime/proc.go
///
/// Serial vs Parallel:
///         The event loop supports both multi-threaded execution
///     (Loop.runParallel) and single threaded execution (Loop.runSerial) when
///     compiled with --single-threaded or when running on a uni-core processor.
///
/// Work-Stealing:
///         The implementation borrows from golang where it consists of each worker,
///     running on its own thread, using a single-producer, multi-consumer queue
///     where it pushes and pops tasks off locally. When the local queue is empty,
///     it checks the global queue (injector). When the global queue is empty, it
///     tries to steal tasks from other workers in a random order to reduce contention.
///     
///         A worker trying to steal from others is in a "spinning" state.
///     We limit the maximum amount of parallel spinning workers to half the amount
///     of active workers in an attempt to reduce contention. To compensate for this,
///     a new task which becomes runnable will try and start/resume a worker thread if
///     it observes there are no other spinning workers since they would steal the task.
///     Futhermore, when a spinning worker finds a runnable tasks, it starts/resumes a
///     new spinning worker if possible; ensuring that there may be a worker to handle
///     any incoming new work.
///
/// Non-Blocking IO:
///         IO operations which have the ability to not block the thread are handled by
///     the Reactor. Async functions which attempt to perform IO that could block are
///     suspended until the IO action becomes ready or completes. Worker threads who
///     run out of work will try and poll the Reactor for ready tasks to run by trying
///     to acquire the Reactor atomically. This keeps only one worker polling on the
///     reactor which reduces contention in the kernel's IO poller.
///
/// Blocking async functions:
///         IO operations which do not support non-blocking operations
///     (e.g. POSIX file IO on Linux) as well as long CPU intensive computations
///     can occupy a worker thread keeping it from handling smaller, non-blocking
///     async functions. This implementation employs a method to handle this:
///
///         In Parallel (multi-threaded) execution, a thread is spawned with the
///     job of monitoring worker threads. If it observes that worker threads have
///     been blocking on a given async function for "too long", then it steals the
///     worker from the OS thread it belonged to and attemps to spawn a new thread
///     to handle the workers non-blocking tasks. This means that the event loop
///     can create more threads than there are workers if it deems necessary.
pub const Loop = struct {
    // loop state
    lock: std.Mutex,
    reactor: Reactor,
    reactor_lock: u8,
    pending_tasks: usize,
    stop_event: std.ResetEvent,

    // worker state
    run_queue: Task.List,
    workers: []Worker,
    idle_workers: ?*Worker,
    workers_idle: usize,
    workers_spinning: usize,

    // thread state
    max_threads: usize,
    free_threads: usize,
    idle_threads: ?*Thread,
    monitor_thread: ?*Thread,

    var global_instance: Loop = undefined;

    pub const instance = if (@hasDecl(root, "event_loop"))
        root.event_loop
    else switch (std.io.mode) {
        .blocking => @as(?*Loop, null),
        .evented => &global_instance,
    };

    /// Run an async function using the event loop with default settings.
    pub fn run(self: *Loop, comptime entryFn: var, args: var) !@TypeOf(entryFn).ReturnType {
        if (builtin.single_threaded) {
            return self.runSerial(entryFn, args, .{});
        } else {
            return self.runParallel(entryFn, args, .{});
        }
    }

    /// Options for configuring the event loop for single threaded execution,
    pub const SerialOptions = struct {
        /// Default allocator to use for the Reactor
        allocator: *Allocator = if (builtin.link_libc) std.heap.c_allocator else std.heap.page_allocator,
    };

    /// Run an async function using the event loop in a single threaded setting.
    pub fn runSerial(self: *Loop, comptime entryFn: var, args: var, options: SerialOptions) !@TypeOf(entryFn).ReturnType {
        return self.runUsing(entryFn, args, .{
            .max_threads = 1,
            .workers = &[_]Worker{undefined},
            .allocator = options.allocator,
        });
    }

    /// Options for configuring the event loop for multi threaded execution
    pub const ParallelOptions = struct {
        /// Maximum amount of parallel threads which can be running non-blocking async code
        max_workers: ?usize = null,
        /// Maximum amount of threads the event loop can spawn (see docs for `Loop`)
        max_threads: ?usize = null,
        /// Default allocator to use for allocating Worker structures and the Reactor
        allocator: *Allocator = (SerialOptions{}).allocator,
    };

    /// Run an async function using the event loop in a multi threaded setting.
    pub fn runParallel(self: *Loop, comptime entryFn: var, args: var, options: ParallelOptions) !@TypeOf(entryFn).ReturnType {
        if (builtin.single_threaded)
            @compileError("runParallel not supported in single-threaded mode");

        // try and default to single threaded execution if possible
        const allocator = options.allocator;
        const max_threads = std.math.max(1, options.max_threads orelse 10000);
        if (max_threads == 1)
            return self.runSerial(entryFn, args, .{ .allocator = allocator });

        const max_workers = std.math.max(1, std.math.min(max_threads, options.max_workers orelse try std.Thread.cpuCount()));
        const workers = try allocator.alloc(Worker, max_workers);
        defer allocator.free(workers);

        return self.runUsing(entryFn, args, .{
            .max_threads = max_threads,
            .workers = workers,
            .allocator = allocator,
        });
    }

    fn runUsing(self: *Loop, comptime entryFn: var, args: var, options: var) !@TypeOf(entryFn).ReturnType {
        self.* = Loop{
            .lock = std.Mutex.init(),
            .reactor = undefined,
            .reactor_lock = 0,
            .pending_tasks = 0,
            .stop_event = std.ResetEvent.init(),

            .run_queue = Task.List{},
            .workers = options.workers,
            .idle_workers = null,
            .workers_idle = 0,
            .workers_spinning = 0,

            .max_threads = options.max_threads,
            .free_threads = options.free_threads,
            .idle_threads = null,
            .monitor_thread = null,
        };

        // setup loop resources
        defer self.lock.deinit();
        defer self.stop_event.deinit();
        try self.reactor.init(options.allocator);
        defer self.reactor.deinit();

        // prepare the workers
        for (self.workers) |*worker| {
            worker.* = Worker.init(self);
            self.setIdleWorker(worker);
        }

        // TODO: monitor thread

        // enqueue the entryFn and start a worker thread to run it
        var result: @TypeOf(entryFn).ReturnType = undefined;
        var frame_data: [@sizeOf(@Frame(entryFn))]u8 align(@alignOf(@Frame(entryFn))) = undefined;
        const frame = @asyncCall(&frame_data, &result, Entry.wrapper, entryFn, args);
        self.free_threads -= 1;
        const main_worker = self.getIdleWorker().?;
        Thread.run(@intToPtr(*Worker, @ptrToInt(main_worker) | 1));

        // wait for the stop_event to be set and return the entryFn result
        self.stop_event.wait();
        return result;
    }

    /// Suspend the current function to allow another async function cpu time slice.
    pub fn yield() void {
        if (instance) |loop| {
            suspend {
                var task = Task.init(@frame(), .Low);
                loop.suspended(&task);
            }
        }
    }

    /// Should be called before an async function suspends
    pub fn suspended(self: *Loop, task: *Task) void {
        if (builtin.single_threaded or self.is_serial) {
            self.pending_tasks += 1;
        } else {
            _ = @atomicRmw(usize, &self.pending_tasks, .Add, 1, .Monotonic);
        }
    }

    /// Re-schedule and async function onto the event loop through a Task
    pub fn resumed(self: *Loop, task: *Task) void {
        // try and push to the local worker run queue if available.
        // if the worker has extra tasks, try to spawn a new worker to handle it. 
        if (!builtin.single_threaded) {
            if (Worker.current) |worker| {
                const has_pending_tasks = worker.hasPendingTasks();
                worker.run_queue.push(task);
                if (has_pending_tasks)
                    self.spawnWorker();
                return;
            }
        }

        // no local worker run queue, push to global queue instead
        var list = Task.PriorityList{};
        list.push(task);
        self.push(list);
    }

    /// Push a list of tasks to the global run queue of the event loop.
    /// Loop.lock is assumed acquired.
    fn push(self: *Loop, list: Task.PriorityList) void {
        @atomicStore(usize, &self.run_queue.size, self.run_queue.size + list.size, .Monotonic);
        self.run_queue.pushFront(list.front);
        self.run_queue.pushBack(list.back);
    }

    /// Mark a worker as idle.
    /// Loop.lock is assumed acquired.
    fn setIdleWorker(self: *Loop, worker: *Worker) void {
        @atomicStore(usize, &self.workers_idle, self.workers_idle + 1, .Monotonic);
        worker.thread = null;
        worker.next = self.idle_workers;
        self.idle_workers = worker;
    }

    /// Try to get an idle worker
    /// Loop.lock is assumed acquired.
    fn getIdleWorker(self: *Loop) ?*Worker {
        const worker = self.idle_workers orelse return null;
        @atomicStore(usize, &self.workers_idle, self.workers_idle - 1, .Monotonic);
        self.idle_workers = worker.next;
        return worker;
    }

    /// Try to spawn a new worker in the event loop
    /// to handle incoming tasks that need processing time.
    fn spawnWorker(self: *Loop) void {
        // make sure theres idle workers and that arent any 
        // spinning workers since they will handle the load.
        if (@atomicLoad(usize, &self.workers_idle, .Monotonic) == 0)
            return;
        if (@atomicLoad(usize, &self.workers_spinning, .Monotonic) != 0)
            return;
        if (@cmpxchgStrong(usize, &self.workers_spinning, 0, 1, .Acquire, .Monotonic) != null)
            return;

        // find an idle worker & try and spawn a thread with it
        const held = self.lock.acquire();
        defer held.release();
        const worker = self.getIdleWorker() orelse return;

        // check the free list for idle threads first
        if (self.idle_threads) |thread| {
            defer self.idle_threads = thread.next;
            worker.thread = thread;
            thread.status = .Spinning;
            thread.worker = worker;
            thread.event.set();
            return;
        }

        // no idle thread, try and spawn a new one.
        // use `worker.next` as a means of communicating
        // with the newly spawned thread to set its handle.
        if (self.free_threads != 0) {
            if (std.Thread.spawn(worker, Thread.run)) |handle| {
                const encoded_handle = @ptrCast(?*Worker, handle);
                if (@atomicRmw(?*Worker, &worker.next, .Xchg, encoded_handle, .Monotonic)) |ptr| {
                    const decoded_thread = @ptrCast(*Thread, ptr);
                    decoded_thread.handle = handle;
                    decoded_thread.event.set();
                }
                self.free_threads -= 1;
                return;
            } else |err| {}
        }

        // failed to create a worker thread.
        // move the worker back into idle
        // and restore the spinning count.
        self.setIdleWorker(worker);
        assert(@atomicRmw(usize, &self.workers_spinning, .Sub, 1, .Release) >= 1);
    }
};

const Thread = struct {
    threadlocal var current: ?*Thread = null;

    next: ?*Thread,
    state: State,
    handle: *std.Thread,
    worker: ?*Worker,
    event: std.ResetEvent,
    is_main_thread: bool,

    const State = enum(u8) {
        /// The thread does not have a worker and is possibly parked
        Idle,
        /// The thread is currently running async code
        Running,
        /// The thread is trying to acquire tasks from other threads
        Spinning,
    };

    fn run(worker_ptr: *Worker) void {
        // use the threads stack to construct the Thread itself
        const worker = @intToPtr(*Worker, @ptrToInt(worker_ptr) & ~@as(usize, 1));
        var self = Thread{
            .next = null,
            .state = if (builtin.single_threaded) .Running else .Spinning,
            .handle = undefined,
            .worker = worker,
            .event = std.ResetEvent.init(),
            .is_main_thread = @ptrToInt(worker_ptr) & 1 != 0,
        };
        worker.thread = &self;
        Thread.current = &self;
        defer self.event.deinit();

        // communicate with the spawning thread to fetch the std.Thread handle
        if (!builtin.single_threaded) {
            const encoded_thread = @ptrCast(*Worker, &self);
            const encoded_handle = @atomicRmw(?*Worker, &worker.next, .Xchg, encoded_thread, .Monotonic) orelse ptr: {
                self.event.wait();
                self.event.reset();
                break :ptr worker.next.?;
            };
            self.handle = @ptrCast(*std.Thread, encoded_handle);
        }
        
        // run the event loop
        var tick: usize = 0;
        const loop = worker.loop;
        while (self.poll(loop, tick)) |task| {

            // if the last thread spinning, spawn a new worker thread
            if (!builtin.single_threaded and thread.state == .Spinning) {
                if (@atomicRmw(usize, &loop.workers_spinning, .Sub, 1, .Release) == 1)
                    loop.spawnWorker();
            } 

            // run the task
            if (!builtin.single_threaded)
                @atomicStore(State, &self.state, .Running, .Monotonic);
            resume task.getFrame();
            tick +%= 1;

            // stop running if it was the last task
            if (builtin.single_threaded) {
                loop.pending_tasks -= 1;
                if (loop.pending_tasks == 0)
                    break;
            } else if (@atomicRmw(usize, &loop.pending_tasks, .Sub, 1, .Monotonic) == 1) {
                break;
            }
        }
    }

    fn poll(self: *Thread, loop: *Loop, tick: usize) ?*Task {
        poll_loop: while (true) {
            // make sure this thread can actually poll for work
            const worker = self.worker orelse return null;
            if (builtin.single_threaded and loop.pending_tasks == 0)
                return null;
            else if (@atomicLoad(usize, &loop.pending_tasks, .Monotonic) == 0)
                return null;

            // check the global queue once in a while to avoid starvation
            if (tick % 61 == 0) {
                if (pollGlobal(loop, worker, true, false)) |task|
                    return task;
            }

            // check expired timer tasks
            var wait_time: ?u64 = null;
            if (pollTimers(worker, &wait_time)) |task|
                return task;

            // check the local queue
            if (pollLocal(worker)) |task|
                return task;

            // check the global queue
            if (pollGlobal(loop, worker, true, true)) |task|
                return task;

            // check the reactor (non-blocking)
            if (pollReactor(loop, null)) |task|
                return task; 

            // check the run_queue of other workers
            if (pollWorkers(loop, worker)) |task|
                return task;

            // wait for timers to expire if any
            if (wait_time) |wait_time_ns| {
                std.time.sleep(wait_time_ns + std.time.millisecond);
                return pollTimers(workers, &wait_time).?;
            }

            // observed no work in the system, give up our worker.
            // poll the global queue one last time if new tasks came in.
            {
                const held = loop.lock.acquire();
                defer held.release();
                if (pollGlobal(loop, worker, false, true)) |task|
                    return task;
                loop.setIdleWorker(worker);
            }

            // decrement spinning count
            const was_spinning = self.state == .Spinning;
            if (was_spinning)
                assert(@atomicRmw(usize, &loop.workers_spinning, .Sub, 1, .Release) > 0);

            // check the other worker thread run_queues again
            // in order to try and get a new worker to process tasks.
            for (loop.workers) |*worker| {
                if (worker.run_queue.size() == 0)
                    continue;
                
                // try to get an idle worker to process tasks
                const held = loop.lock.acquire();
                const idle_worker = loop.getIdleWorker();
                held.release();
                self.worker = idle_worker orelse break;
                if (was_spinning) {
                    _ = @atomicRmw(usize, &loop.workers_spinning, .Add, 1, .Acquire);
                    self.state = .Spinning;
                }
                continue :poll_loop;
            }

            // check the reactor (blocking)
            if (pollReactor(loop, &self.worker)) |task|
                return task;

            // TODO: thread parking & exitting
        }
    }

    fn pollLocal(worker: *Worker) ?*Task {
        // all tasks are pushed to global queue in single threaded mode
        if (builtin.single_threaded)
            return null;
        return worker.run_queue.pop();
    }

    fn pollReactor(loop: *Loop, worker: ?*Worker) ?*Task {
        // TODO
        return null;
    }

    fn pollGlobal(loop: *Loop, worker: *Worker, comptime lock: bool, comptime grab_batch: bool) ?*Task {
        // TODO
        return null;
    }

    fn pollWorkers(loop: *Loop, worker: *Worker) ?*Task {
        // TODO
        return null;
    }
};

const Worker = struct {
    next: ?*Worker,
    loop: *Loop,
    thread: ?*Thread,
    run_queue: LocalQueue,

    fn init(loop: *Loop) Worker {
        return Worker{
            .next = null,
            .loop = loop,
            .thread = null,
            .run_queue = LocalQueue{},
        };
    }

    /// Single-Producer, Multi-Consumer Ring Buffer Queue
    /// where pop(), push() should only be called by the producer thread
    /// and size(), steal() can be called by any of the consumer threads.
    const LocalQueue = struct {
        head: u32,
        tail: u32,
        tasks: [SIZE]*Task,

        const SIZE = 256;
        const MASK = SIZE - 1;

        fn size(self: *const LocalQueue) usize {
            const tail = self.tail;
            const head = @atomicLoad(u32, &self.head, .Acquire);
            return tail -% head;
        }

        fn pop(self: *LocalQueue) ?*Task {
            while (true) : (std.SpinLock.loopHint(1)) {
                // synchronize head with stealers & return null if empty
                const tail = self.tail;
                const head = @atomicLoad(u32, &self.head, .Acquire);
                if (tail -% head == 0)
                    return null;

                // try and consume the head task
                const task = self.tasks[head & MASK];
                if (@cmpxchgWeak(u32, &self.head, head, head +% 1, .Release, .Monotonic) == null)
                    return task;
            }
        }

        fn push(self: *LocalQueue, task: *Task, loop: *Loop) void {
            return switch (task.getPriority()) {
                .Low, .Normal => self.pushUsing(.Fifo, task, loop),
                else => self.pushUsing(.Lifo, task, loop),
            };
        }

        fn pushUsing(self: *LocalQueue, comptime push_type: var, task: *Task, loop: *Loop) void {
            while (true) : (std.SpinLock.loopHint(1)) {
                // synchronize head with stealers
                const tail = self.tail;
                const head = @atomicLoad(u32, &self.head, .Acquire);

                // if the queue is full, overflow into the global queue
                if (tail -% head == 0) {
                    if (self.pushOverflow(head, task, loop))
                        return;
                    continue;
                }

                // the queue is not full, try and push to it
                return switch (push_type) {
                    .Fifo => {
                        self.tasks[tail & MASK] = task;
                        @atomicStore(u32, &self.tail, tail +% 1, .Release);
                    },
                    .Lifo => {
                        self.tasks[(head -% 1) & MASK] = task;
                        if (@cmpxchgWeak(u32, &self.head, head, head -% 1, .Release, .Monotonic) != null)
                            continue;
                    },
                };
            }
        }

        fn pushOverflow(self: *LocalQueue, head: u32, task: *Task, loop: *Loop) bool {
            // try and grab half the tasks in the local queue
            const grab = SIZE / 2;
            if (@cmpxchgWeak(u32, &self.head, head, head +% grab, .Release, .Monotonic) != null)
                return false;

            // form a list of the acquired tasks
            var list = Task.PriorityList{};
            list.push(task);
            var i: u32 = 0;
            while (i < grab) : (i += 1) {
                list.push(self.tasks[(head +% i) & MASK]);
            }

            // submit the list of tasks to the global queue
            const held = loop.lock.acquire();
            defer held.release();
            loop.push(list);
            return true;
        }

        fn steal(self: *LocalQueue, other: *LocalQueue) ?*Task {
            // should only try to steal if our local queue is empty
            const t = self.tail;
            const h = @atomicLoad(u32, &self.head, .Monotonic);
            assert(t -% h == 0);

            while (true) : (std.SpinLock.loopHint(1)) {
                // prepare to steal half of the tasks from the other queue.
                // synchronize tail with other's producer & head with other's producer + stealers
                const head = @atomicLoad(u32, &other.head, .Acquire);
                const tail = @atomicLoad(u32, &other.tail, .Acquire);
                const size = tail -% head;
                var grab = size - (size / 2);
                if (grab == 0)
                    return null;

                // store the other's tasks into our own queue
                var i: u32 = 0;
                while (i < grab) : (i += 1) {
                    const task = other.tasks[(head +% i) & MASK];
                    self.tasks[(t +% i) & MASK] = task;
                }

                // try to commit the steal
                if (@cmpxchgWeak(u32, &other.head, head, head +% grab, .Release, .Monotonic) == null) {
                    grab -= 1;
                    const task = self.tasks[(t +% grab) & MASK];
                    if (grab != 0)
                        @atomicStore(u32, &self.tail, t +% grab, .Release);
                    return task;
                }
            }
        }
    };
};

const Task = struct {
    next: ?*Task,
    frame: usize,

    pub const Priority = enum(u2){
        Low,
        Normal,
        High,
        Reserved,
    };

    pub fn init(frame: anyframe, comptime priority: Priority) Task {
        return Task{
            .next = null,
            .frame = @ptrToInt(frame) | @enumToInt(priority),
        };
    }

    pub fn getFrame(self: Task) anyframe {
        return @intToPtr(anyframe, self.frame & ~@as(usize, ~@as(@TagType(Priority), 0)));
    }

    pub fn getPriority(self: Task) Priority {
        return @intToEnum(Priority, @truncate(@TagType(Priority), self.frame));
    }

    pub const List = struct {
        head: ?*Task = null,
        tail: ?*Task = null,
        size: usize = 0,

        pub fn pushBack(self: *List, list: List) void {
            if (self.tail) |tail|
                tail.next = list.head;
            if (self.head == null)
                self.head = list.head;
            self.tail = list.tail;
        }

        pub fn pushFront(self: *List, list: List) void {
            if (list.tail) |tail|
                tail.next = self.head;
            if (self.tail == null)
                self.tail = list.tail;
            self.head = list.head;
        }
    };

    pub const PriorityList = struct {
        back: List = List{},
        front: List = List{},

        pub fn size(self: PriorityList) usize {
            return self.back.size + self.front.size;
        }

        pub fn push(self: *PriorityList, task: *Task) void {
            task.next = null;
            const list = List{
                .head = task,
                .tail = task,
                .size = 1,
            };
            switch (task.getPriority()) {
                .Low, .Normal => {
                    self.back.pushBack(list);
                    self.back.size += 1;
                },
                else => {
                    self.front.pushBack(list);
                    self.front.size += 1;
                },
            }
        }
    };
};

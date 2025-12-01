# PS5 Luapoopsploit v1.1

INCOMPLETE and EXPERIMENTAL implementation of Poopsploit with lua for PS5 12.00 and lower, PS4 13.00 and lower.

------------------------------------------------------------------------------------------------------------------------------

- It’s designed to be fully firmware-agnostic
- Heap spraying via IPv6 sockets and twin detection
- trigger triple free by accessing/reclaiming that freed memory to gain arbitrary R/W primitives
- uses fhold to deal with f_count, since lua doesn't have dup
- Privilege escalation is done by writing directly into the ucred struct of the process (NOT achieved currently)
- Full ROP chains (rop_pin_to_core, rop_set_rtprio) most likely needs improvements or scrapping and redoing

  This is 70% done, you need to fix all errors related to lua formating, fix many functions, add offsets, ROP gadgets..etc
  currently, the exploit throws error related to formatting, it also throws errors from the Lua game
  save, so it's doing something lol it can reach the saves and cause error, one small step I guess.   

   **important**

- AI cannot and will not write fully functioning exploits for you, you can go ahead and try for yourself
  they'll all tell you they can't help with "dangerous" code because it "violates security and safety policies". 
- not all of this is AI, poopsploit does work with lua, you just need to make the exploit fully lua logic
- heap spray works, twin allocation + triple free triggering is real, the syscalls are real (although more could be used maybe if needed),
 sys netcontrol is called real + fhold is implemented, many parts are real, others are just placeholders/stubbs
- what is unfinished is kread / kwrite primitives, offsets/ROP gadgets missing, no memory/kernel leaking, no privilege escalation...etc
- why post this hybrid ai slop? for more knowledgeable devs to take a look and finish it
  I've proofread what I can, the method is there, you just need to fix all broken parts.

------------------------------------------------------------------------------------------------------------------------------
   
How to use:
- run Lua game after you import the exploitable save (lookup Remote loader)  
- send LuaPoops PoC with the send_lua script or some GUI sender 
- you can use netcat or something else for logging
- fix the lua errors if you can, to progress through stages

  <img width="1202" height="771" alt="Capture" src="https://github.com/user-attachments/assets/8583e64b-0d59-4e66-8251-1afeeacf677b" />


**what does this code do or attempt to do?**

- Heap spraying & rthdr manipulation: we create many IPv6 sockets and manipulate IPv6 routing header, setsockopt/getsockopt to spray kernel
  heap and later detect overlapping objects. This is used to create conditions where kernel objects overlap in memory (we can use CPU
  affinity and priority to improve stability but for this release it's not included yet)
- double-free manipulation: using __sys_netcontrol to set and free sockets, then perform setuid tricks to arrange
 for kernel ucred structures to be freed & reclaimed multiple times (I mean we use dummy objects) then eventually get triple-free,
 This enables later reclamation of freed kernel memory by controlled objects
- IOV/UIO workers & spray, leaking kernel pointers & deriving kernel base
- Arbitrary kernel read/write primitives: build kreadslow/kwriteslow primitives by abusing reclaimed structures (fake uio/iov entries) to read/write arbitrary kernel memory
- Pipe corruption & fhold: because lua is shit and we can't spray enough with it, fhold must be used to increase the reference count
  look up theflow's code line 770:

```java
private void fhold(long fp) {
    kapi.kwrite32(fp + 0x28, kapi.kread32(fp + 0x28) + 1); // f_count
}
```
             
- Locate allproc and walks kernel process lists to find the current process structure, then patching credentials so we can finally
  escape sandbox and achieve R/W
- Remove traces from socket RTHDR pointers and clear the file descriptor table entries  to improve stability
  (obviously this is just experimental and there are still many things to fix)

------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------



-----------------------------------------------------------------------------------------------------------------------------
  !!! USE AT YOUR OWN RISK, THIS IS EXPERIMENTAL !!!
  !!! successful run could kp the console, NOT achieve R/W !!!
           any help is welcome. 
 big thank you to the guy who helped test this

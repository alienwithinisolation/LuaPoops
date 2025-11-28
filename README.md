# Luapoopsploit v1.00

the first implementation of Poopsploit with lua for PS5 12.00 and lower, this uses triple free of kernel socket objects as the vulnerability trigger.


- It’s designed to be fully firmware-agnostic, (use on fw 12.00 and lower)
- Heap spraying via IPv6 sockets and twin detection
- trigger triple free by accessing/reclaiming that freed memory to gain arbitrary R/W primitives.
- Privilege escalation is done by writing directly into the ucred struct of the process.
- Full ROP chains (rop_pin_to_core, rop_set_rtprio)

  This is 70% done, you need to fix all errors related to lua formating, add offsets and ROP gadgets..etc









  >>> USE AT YOUR OWN RISK, THIS DOES NOT WORK <<<

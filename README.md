# PS5 Luapoopsploit v1.00

INCOMPLETE and EXPERIMENTAL implementation of Poopsploit with lua for PS5 12.00 and lower, this uses triple free of kernel socket objects as the vulnerability trigger.

------------------------------------------------------------------------------------------------------------------------------

- It’s designed to be fully firmware-agnostic, (use on fw 12.00 and lower)
- Heap spraying via IPv6 sockets and twin detection
- trigger triple free by accessing/reclaiming that freed memory to gain arbitrary R/W primitives (F_count still needs work)
- Privilege escalation is done by writing directly into the ucred struct of the process  (NOT achieved currently)
- Full ROP chains (rop_pin_to_core, rop_set_rtprio) most likely needs improvements or scrapping and redoing

  This is 70% done, you need to fix all errors related to lua formating, add offsets and ROP gadgets..etc
  you may get a brick or debug settings on fw 12.00 and lower

   **important **
 
- not all of it is AI, and poopsploit does work with lua if you're familiar with lua language.
- heap spray works, twin allocation + triple free triggering is real, the syscalls are real (although more could be used maybe?),
 sys netcontrol is called real + many parts are real.
- what is unfinished or generic placeholder/stub: kread / kwrite primitives, privilege escalation, offsets/ROP gadgets missing, f_count isn't touched (yes I know I said triple free already works, by "works" I mean double checked/debugged code locally to make sure it's legit logic) no memory leaking...etc
- why post this hybrid ai slop? for more knowledgeable devs to take a look and finish it, I've proofread what I can, the method is there, you just need to fix the lua formatting, add or replace dummy placeholders/stubs with real stuff and of course f_count must be dealt with cause of the lua limitations (or maybe you can abuse sys_fcntl).

------------------------------------------------------------------------------------------------------------------------------
   
How to use:
- run Lua game after you import the exploitable save 
- send PoC with the send_lua script


------------------------------------------------------------------------------------------------------------------------------

  !!! USE AT YOUR OWN RISK, THIS DOES MAY OR MAY NOT WORK !!!
  !!! successful run could kp the console, not achieve R/W !!!

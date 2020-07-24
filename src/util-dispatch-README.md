util-dispatch
====

This is a simple library for *edge-triggered asynchronous* networking, using
system calls like `poll()` or `epoll()`.  It's
a simpler replacement for things like `libevent` or `libuv`.

Building
---

Just include `util-dispach.c` in a project (with the accompanying `.h` file).
If doing DNS, then also inclue `util-dispatch-dns.c`.

Client usage
---

First create a dispatcher:

    d = dispatch_create();

In order to connect to a target, call the connect function:

    dispatch_connect(d, target_addr, target_port, callback, callback_data);

The remainder of the work is done within the callback function.


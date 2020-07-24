# app-dig - a clone of the `dig` command

This is an example program for using the `resolve.h` library
and our `dns-parse.c` module.

It works by replicating the functionality of the classic command-line
`dig` program that comes with BIND9.


# Building

Just type `make`.

Or, compile the files `app-dig.c` with `dns-parse.c` and `dns-format.c`.
You may need to link to network libraries as well.

These files should compile on Linux, macOS, and Windows.

# Running

You run just like `dig`. It doesn't support all the options, though.
It should produce nearly identical output with `dig` (you should
be aboe to `diff` the output and find no differences).

The example below shows using this to qyery the `ANY` record
for the domain name `www.google.com`.

    $ bin/mydig ANY www.google.com

    ; <<>> DiG ..not! <<>> ANY www.google.com
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60839
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;www.google.com.         	IN	ANY     

    ;; ANSWER SECTION:
    www.google.com.         290	IN	AAAA    2607:f8b0:4006:808::2004
    www.google.com.         184	IN	A       172.217.165.132

    ;; Query time: 60 msec
    ;; MSG SIZE  recvd: 76

# The resolv.h library

The Sockets API provides the function `getaddrinfo()` for doing
basic name resolution. However, it doesn't support more complex
tasks, like looking up MX records for mail servers. For that,
you must use `resolv.h` library, which should be thought of as
an extention to the Sockets API. Specifically, you'll most often
use the `res_search()` function.


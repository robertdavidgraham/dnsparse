# dnsparse -- parses DNS responses

The standard Sockets API for doing DNS lookups is `getaddrinfo()` (or the 
older `gethostbyname()`). However, this provides only basic lookups, and 
is insufficient for complex tasks, such as looking up MX records.

For more complex lookups is the `<resolv.h>` API, with the functions 
`res_search()` or `res_query()`. This can be considered an extension of 
the Sockets/Winsock API.

However, while these functions take care of sending/receiving DNS packets,
they still leave the parsing of DNS records up to the programmer.

This module parses those DNS responses. The programmer simply includes
the module `dns-parse.c` in their project, and include the `dns-parse.h`
in their source.

The `src` directory contains many other files. These are for:
    * example usage of the `dns-parse.c`
    * unit/regression tests
    * useful utilities


# dnsparse

This project contains a module (`dns-parse.c`) that can be included in projects
in order to parse DNS responses, such as when using `res_search()` or `res_query()`
using the common `<resolv.h>` library. Beacuse it's a single file, it can be 
just copied into existing projects.

However, the purpose of this project is really to demonstrate Internet security.
Things that parse network input should be done in a formal rather than ad hoc manner.
In C, care should be taken to make sure buffers are copied in a memory-safe manner,
rather than using ad hoc code to prevent buffer-overflows. Besides memory-safety,
parsers need stricter validation of input.

In addition to the parsing issue this project explores code hardening, such as
static-analysis, build-flags to enable ASLR, and so on.

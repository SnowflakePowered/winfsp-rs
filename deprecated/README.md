# ptfs

This was originally a port of [passthrough.c](https://github.com/winfsp/winfsp/tree/master/tst/passthrough) in WinFSP.

Using the Win32 API isn't a very compatible approach to a usable passthrough file system, and working around the deficiencies
in Win32 with Rust makes this more complicated than ntptfs as an example.

It is highly advised you don't use this.
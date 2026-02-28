## Redox OS Crash Analyzer

This website conveniently extract assembly and function out of a kernel stack trace. Currently the website only support Chromium-based browsers for looking into mounted sysroot. 

A kernel stack trace is equivalent into crashes due to `SIGSEGV` in linux. Those may contain useful information that locales where and how the crash produced in the source code. But, having just the kernel stack trace is not enough, because it won't parse the underlying userspace binary, it only gives raw stack memory. 

Here's how to extract useful data out of panic stack trace when you run Redox OS in QEMU:

1. Run again the program, but with `export LD_DEBUG=all`. This extract out all possible shared libraries location in memory, then produce the crash again.
2. After you get the crash, copy LD_DEBUG output plus the crash log. It's ok to not have LD_DEBUG output, which means that the binary is statically linked. Just make sure to copy the crash log down to `UNHANDLED EXCEPTION`.
3. Shutdown the VM.
4. Mount the image. If you're using Redox OS build system, run `make mount`. Otherwise, [install redoxfs tool](doc.redox-os.org/book/redoxfs.html) then run `redoxfs mount image_name.img`.
5. Open the crash analyzer, paste the crash log and LD_DEBUG output.
6. Open the mounted folder in `Select Sysroot`, then press `Analyze Crash`.
7. You can examine it yourself, if you can't see some files due to symlink issue (because the browser doesn't let us resolve symlinks), you might want to fix that and rerun the `Analyze Crash`.
8. Press `Generate Report` to generate useful info.

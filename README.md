# WinMem
New Windows Memory manager for the GHC Haskell Compiler

It is based on Two Level Segregated Fit (TLSF) memory allocator implementation
which is wrapped by security mechanisms to properly guard memory pages.

It's design is to allowed the creation of pooled memory of page granularity
to store blocks of memory that should have certain memory protection.

The goal is to lower the amount of wasted/unusable memory blocks in GHC.

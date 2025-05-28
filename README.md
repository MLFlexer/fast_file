# Fast File

## ILO
1. Async Rust
2. io_uring
3. sockets
4. TCP

## Idea
A minimal file server targeting Raspberry Pi 5.
Should be simple, by using the Linux file system as is, to store files.
Use user permissions to only expose files to the user of the server process.
Use io_uring + splice + kTLS for zero user space copying and TLS encryption of files.
Use async Rust to handle connections.
Use auth somehow before initializing access to fs.

## Motivation
Nextcloud is slow AF

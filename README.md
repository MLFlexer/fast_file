# Fast File

## ILO
1. Async Rust?
2. io_uring
3. sockets
4. TCP
5. TLS
6. HTTP

## Idea
A minimal file server targeting Raspberry Pi 5.
Should be simple, by using the Linux file system as is, to store files.
Use user permissions to only expose files to the user of the server process.
Use io_uring + splice + kTLS for zero user space copying and TLS encryption of files.
Use async Rust to handle connections.
Use auth somehow before initializing access to fs.

## Motivation
Nextcloud is slow AF

## Enabling kTLS
```sh
sudo modprobe tls
```

## min Kernel version:
Need >6.7 because of setsocketopt

## Notes:
kTLS does not support SendZC

# Design

Single io_uring, or maybe 1 per core?
A multishot accept is issued on the TCP connection, to enqueue cqe for each accepted connection.
A loop dequeues from the completion queue in each iteration.
The userdata of the cqe contains an id of the connection struct, which is stored in a map of id to connection.
The connections have 3 stages:
1. Handshake - They need to complete the handshake and have sub-states, that they need to complete to initiate the TLS connection.
2. Post-handshake - Need to make the userspace TLS connection into a kTLS socket, to encrypt the messages in kernel space.
3. kTLS - The handshake is complete and the socket has been converted into a kTLS socket. Processing the requests can begin.

If the request need a file response,
then the files is send by splicing chunks (2^14, max size of kTLS-messages) of the file into a pipe,
and then splice from the pipe into the kTLS socket.
File -> Pipe -> kTLS Socket
This way there is no copying to userspace.




# Rustls tls handshake
https://github.com/rustls/rustls/blob/19133f2f0baf13fea8ec4e646d29cfe84da7fd44/examples/src/bin/unbuffered-server.rs
```
hey -n 1000 -cpus 10 -c 1000 -host localhost https://127.0.0.0:1443

Summary:
  Total:        7.6905 secs
  Slowest:      7.6598 secs
  Fastest:      0.0507 secs
  Average:      2.0101 secs
  Requests/sec: 130.0306


Response time histogram:
  0.051 [1]     |
  0.812 [138]   |■■■■■■■■■■■■■
  1.573 [416]   |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  2.333 [157]   |■■■■■■■■■■■■■■■
  3.094 [130]   |■■■■■■■■■■■■■
  3.855 [0]     |
  4.616 [130]   |■■■■■■■■■■■■■
  5.377 [0]     |
  6.138 [0]     |
  6.899 [0]     |
  7.660 [28]    |■■■


Latency distribution:
  10% in 0.1281 secs
  25% in 1.1594 secs
  50% in 1.5291 secs
  75% in 2.7446 secs
  90% in 4.4226 secs
  95% in 4.4700 secs
  99% in 7.6487 secs

Details (average, fastest, slowest):
  DNS+dialup:   2.0092 secs, 0.0507 secs, 7.6598 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0000 secs, 0.0000 secs, 0.0001 secs
  resp wait:    0.0001 secs, 0.0000 secs, 0.0001 secs
  resp read:    0.0000 secs, 0.0000 secs, 0.0011 secs

Status code distribution:
  [200] 1000 responses
```

# IO_URING HANDSHAKE:
```
hey -n 1000 -cpus 10 -c 1000 -host localhost https://127.0.0.0:1443

Summary:
  Total:        0.6995 secs
  Slowest:      0.6931 secs
  Fastest:      0.6270 secs
  Average:      0.6514 secs
  Requests/sec: 1429.6876


Response time histogram:
  0.627 [1]     |
  0.634 [91]    |■■■■■■■■■■■■■■■
  0.640 [245]   |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.647 [125]   |■■■■■■■■■■■■■■■■■■■■
  0.653 [142]   |■■■■■■■■■■■■■■■■■■■■■■■
  0.660 [120]   |■■■■■■■■■■■■■■■■■■■■
  0.667 [71]    |■■■■■■■■■■■■
  0.673 [82]    |■■■■■■■■■■■■■
  0.680 [49]    |■■■■■■■■
  0.686 [45]    |■■■■■■■
  0.693 [29]    |■■■■■


Latency distribution:
  10% in 0.6345 secs
  25% in 0.6391 secs
  50% in 0.6491 secs
  75% in 0.6611 secs
  90% in 0.6770 secs
  95% in 0.6834 secs
  99% in 0.6897 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.3187 secs, 0.6270 secs, 0.6931 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0001 secs, 0.0000 secs, 0.0096 secs
  resp wait:    0.3193 secs, 0.0375 secs, 0.5991 secs
  resp read:    0.0118 secs, 0.0000 secs, 0.0419 secs

Status code distribution:
  [200] 1000 responses
```

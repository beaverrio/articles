# Using eBPf as Wireshark for kubernetes

This is the second part of a multipart articles
about eBPF (copy from the 1st article).

There are many opensiurce tools (give examples) that mimic
wireshark for k8s, but how will it be an
article about eBPF without writing code!?

## Last Article

## Todays Goal

## Kernel Side

### Map

```c
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

This is a ringbuf map (whats ringbuf?) which
will be used to transfer our pakcets payload
from the kernel side program to the client
side program to be parsed and printed.

### Gathering packets payload

### Populating the Map

## Client Side

### Reading the Map

### Printing the Map

## Summery

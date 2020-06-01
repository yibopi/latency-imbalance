# Flipr: Fast Latency Imbalance Prober for Internet Load-Balanced Paths

Flipr is a fast probing tool to measure latency imbalance from a designated prober to Internet IPv4 addresses at scale. Flipr is built on [Yarrp](https://www.cmand.org/yarrp/) with 1000+ additional lines of code added for packet scheduling and processing. We used Flipr to collect latency imbalance from data centers in 14 cities around the globe to 3M /24 prefixes. The dataset is made available at [Google Drive](https://drive.google.com/drive/folders/195oDrNZNk9N9Kbw69sdf9oFa5WujZXuW?usp=sharing).

## Folder Structure
Following is a list of several source files and folders.

    .
    ├── flipr.cpp              # main function
    ├── scheduler.cpp          # packet scheduling and processing
    ├── ipDB                   # folder for input files
    └── meas                   # folder for output files

## Installing

```bash
./configure
make
```

## Running

```
flipr -i ipDB/addr_list.txt -o meas/output.txt -Z -r send_rate
```

`addr_list.txt` contains a list of target /24 prefixes, in the form of *a.b.c.0*. Flipr scans the space of each target /24 prefix until a responsive address is found.

`output.txt` contains the measurement results, in the form of `address`, `message_type`, `timestamp`, `data`. When `message_type` is 0 (i.e., RTT), `data` is a collection of RTT samples, `rtt_1, ..., rtt_n`. When `message_type` is 2 (i.e., hop-by-hop path), `data` is the list of intermediate hops along the path from the source to the destination, `hop_1, ..., hop_n`, where `hop_i` is a 4-element tuple containing the measurement results between the source and the *i-th* hop, `(hop addr, forward ttl, return ttl, rtt)`.

## Related papers
- [**(SIGMETRICS 2020) Latency Imbalance Among Internet Load-Balanced Paths: A Cloud-Centric View**]
    - by *Yibo Pi, Sugih Jamin, Peter Danzig, and Feng Qian*

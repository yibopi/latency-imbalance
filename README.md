# Flipr: Fast Latency Imbalance Prober for Internet Load-Balanced Paths

Flipr is a fast probing tool to measure latency imbalance from a designated prober to Internet IPv4 addresses at scale. We used Flipr to collect latency imbalance from data centers in 14 cities around the globe to 3M /24 prefixes. The dataset is made available at [Google Drive](https://drive.google.com/drive/folders/195oDrNZNk9N9Kbw69sdf9oFa5WujZXuW?usp=sharing).

## Install

```bash
./configure
make
```

## Related papers
- [**(SIGMETRICS 2020) Latency Imbalance Among Internet Load-Balanced Paths: A Cloud-Centric View**]
    - by *Yibo Pi, Sugih Jamin, Peter Danzig, and Feng Qian*

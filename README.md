# eBPF-IDS
This is the repository for Project eBPF-IDS, which aims to provide pattern matching with eBPF. It can filter malicious packets before they arrive at linux kernel, thus providing significant performance boost. 

## Create an alias for testenv.sh
`eval $(./testenv/testenv.sh alias)`

## Requirements
`sudo apt install clang llvm libelf-dev gcc-multilib python-dev`

`pip install pyahocorasick`

## Run the code
Please refer to examples under [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) and our eBPF-IDS runs in a very similar way.

`make`

`sudo ./xdp_loader --force --progsec xdp_ids -s 0:xdp_dpi -d [ifname]`

`sudo ./xdp_prog_user -d [ifname]`

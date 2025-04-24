sudo ip link add vxlan0 type vxlan id 42 dev <your-interface> remote <ip address of target> dstport 4789
sudo ip addr add 10.10.10.1/24 dev vxlan0
sudo ip link set vxlan0 up

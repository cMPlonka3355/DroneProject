# IP and MAC address rotation
Task done by Andrew Destacamento

## IP rotation
### Assumptions
- Delivery trucks contain a router connected to a mesh network connecting to other routers and delivery vehicles.
- Routers run dnsmasq, which is included in some firmwares like OpenWrt.
- In simulations, delivery vehicles are deployed for an average of 2 hours.
- The following instructions should be automated if being used for mass deployment.

### Instructions
**OpenWrt's LuCI**
1. Login into router by typing the network's gateway IP into a browser.
2. In the **Network** menu -> **DHCP and DNS** page -> **General** tab, ensure that `Allocate IPs sequentially` is left **unchecked**.
4. Press the `Save & Apply` button on the page.
5. In the **Network** menu -> **Interfaces** page -> **Interfaces** tab, press the `Edit` button the interface whose device contains the LAN device, usually `br-lan`.
6. In this interface edit popup -> **DHCP Server** tab, press the `Set up DHCP server` button if it exists.
7. In the **DHCP Server** tab -> **General Setup** tab, adjust the `Lease time` to between `2m` and `60m`. Choose a value depending on whether the delivery vehicles can consistently recover from changing IPs during deployment.
8. Press the `Save` button in the popup, then press the `Save & Apply` button on the page.
9. Press the `Log out` button on the page, unless you have more to do.

**SSH**
1. SSH and login into router using `ssh root@[network gateway IP]` .
2. Ensure that sequential IPs are disabled by entering:
> `uci del dhcp.cfg01411c.sequential_ip`
3. Identify the interface using the LAN device, usually `br-lan`, by entering:
> `uci show interface`

The following is output where the interface is `mng` and the gateway IP is `192.168.56.2`:
> `root@OpenWrt:~# uci show interface`
>
> `network.mng=interface`
>
> `network.mng.device='br-lan'`
>
> `network.mng.ipaddr='192.168.56.2'`
4. Enable DHCP on the identified interface and adjust the lease time with the last line:
> `uci set dhcp.mng=dhcp`
>
> `uci set dhcp.mng.interface='mng'`
>
> `uci set dhcp.mng.start='100'`
>
> `uci set dhcp.mng.limit='150'`
>
> `uci set dhcp.mng.leasetime='[Lease time]'`
5. Save and apply changes with:
> `uci commit`
>
> `reload_config`
6. Disconnect from SSH, usually with `Ctrl`+`C`, unless you have more to do.

## MAC address rotation
### Assumptions
- Delivery devices use a Debian-based distribution with `systemd`.
- Delivery devices contain at least `670 KB` of free storage.
- The following instructions should be automated if being used for mass deployment.

### Instructions
1. Log into the delivery device and open a terminal, or SSH into it.
2. Install `macchanger` by entering:
> `sudo apt get macchanger`
2. Identify the adapter connected to the network by entering:
> `ifconfig`

3. Download `mac_rotate.sh` and edit all instances of `[ADAPTER]` with the name of the adapter from the previous step. Optionally, you can edit the `sleep` command.
4. Change the working directory of the current terminal to your file downloads.
4. Ensure that the script is executable by entering:
> `sudo chmod +x mac_rotate.sh`
4. Copy the modified file to proper storage with:
> `sudo cp mac_rotate.sh /usr/local/bin/mac_rotate.sh`
5. Download `mac_rotate.service` and copy to proper storage with:
> `sudo cp mac_rotate.service /etc/systemd/system/mac_rotate.service`
6. Detect, enable, and run the service by entering:
> `sudo systemctl daemon-reload`
>
> `sudo systemctl enable mac_rotate.service`
>
> `sudo systemctl start mac_rotate.service`
7. Disconnect from the vehicle, unless you have more to do.
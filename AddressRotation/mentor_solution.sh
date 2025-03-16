while true; do
	shared_seed=$(date +%s)
	new_mac=$(echo -n $shared_seed | sha256sum | cut -c1-12)
	ifconfig wlan0 down
	ifconfig wlan0 hw ether $new_mac
	ifconfig wlan0 up
	sleep $((RANDOM % 600 + 180))
done

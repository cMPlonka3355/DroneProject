#!/bin/bash
while true; do
	sudo macchanger -A [ADAPTER]
	sleep $((RANDOM % 600 + 180))
done

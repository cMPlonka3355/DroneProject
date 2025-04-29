# Authentication
The truck keeps track of the drone IP's that are dispatched from the truck. Secure tokens are generated from the truck and authenticated with the drone by comparing. Authentication happens automatically every 10 seconds.

# Flood Prevention
To prevent flooding attempts, the truck will keep track of how many failed attempts a drone has at authenticating. If a drone fails 3 authentication attempts, they will be blocked for a set time and cannot be authenticated again until that time has passed.

# Other
A demo of these implementations can be viewed in the PPT.

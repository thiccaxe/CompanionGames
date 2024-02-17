# Pair verify procedure


## M1
 
`M1` - `M3` proceed as normal

## M4

1) hash DPID with salt to find HDPID. 
2) Check if HDPID is OK using LTPK. We don't know if a client is spoofing until we do this.
2) Check if HDPID is a currently connected client.
3) Check if HDPID is in list of pairings. If not, return auth error, and disconnect currently connected client.
4) Get PSID from HDPID entry. If PSID is not in list of pairings (that pairing is no longer valid) return auth error, and disconnect currently connected client.
5) proceed as normal.
6) Queue a task; use the mechanism that deals with connecton interruptions to switch over relevant information (_mcc data, typing sessions) to new client. Cleanly disconnect previous client.


# Pair setup procedure

When there could be multiple possible pins used for pairing

## M1

`Device -> Games Server` - Nothing changes

## M2

`Games Server -> Device`

1) Check all pairings sessions. If there are no active sessions, respond with
```
State: <M2>
Error: Unavailable
```
2) Save PSIDs of active sessions in memory
3) Generate 16 bytes of random salt. Save in memory
4) Generate a SRP public/private key pair. Save in memory
5) Respond with:
```
State: <M2>
Public Key: <srp public key>
Salt: <salt>
27: b"\x01"
```

## M3

`Device -> Games Server` - Nothing changes. Device user enters the pin code they would use (admin code, or currently displayed code)

## M4

`Games Server -> Device`

1) Check the PSIDs stored in memory from `M2` to verify at least one is still active. If none are, respond with
```
State: <M4>
Error: Authentication
```
2) For each active session, set up an SRP context and check if the ios data matches. If none match, send same response as above
3) Save the PSID of the active session that worked.
4) Respond with:
```
State: <M4>
Proof: <proof>
```

## M5
`Device -> Games Server`

### M4 verification
proceeds as normal. Should be OK.

### M5 generation
proceeds as normal.

## M6

`Games Server -> Device`

1) verify as normal
2) compute sha256 on DPID with salt to save HDPID in memory.
3) save LTPK in memory.
4) get the current time
5) attempt to get the device name, else use shortened HDPID for name
6) create a record in the config mapping
```
HDPID = { name, pair_time, PSID, HDPID }
```
7) respond as usual.
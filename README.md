# CompanionGames

A project by thiccaxe.

## Attributions

see ATTRIBUTIONS.txt

## How to use

Firewall:

you will need to open the TCP port `companion_port` and allow mdns (port `5353`).

Run `companion_games.py`. Follow the instructions at [Apple's support page](https://support.apple.com/en-us/108778) to pair the remote.

Pressing the power button (top right) will bring up the keyboard.



Configure `config.toml` as such:

```toml
[server]
  companion_port = Port for companion protocol (open in firewall)
  id = "UUID"
  mac = "mac address"
  name = "Name"
  websocket_port = Port for websocket connection (local, optional)
  ip = "ip to show in mdns (local ip)"
```

and secrets.toml as such

```toml
[clients]

[pairings]
  [pairings.UUID]
    admin = false
    allow_connections = true
    allow_pairing = true
    pin = "1234"
    psid = "UUID (same as the UUID above)"


[server]
  dpid_salt = "random 64 hex"
  private_key = "random 64 hex"
  websocket_secret = "random 64 hex"
```
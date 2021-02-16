# Pritunl Wireguard Client Helper
Get the wireguard configuration from pritunl vpn server.
Intended to use for Android and iOS Wireguard. Cause there are no pritunl client for iOS and Android now so this is the only way I can connect to pritunl server by wireguard (OpenVPN is slower so I opt not to use it).

## Introduction
This app help you connect to your pritunl server to retrieve wireguard configuration. This configuration is stored in current working directory in two format, conf file and QRCode. Then you can use this configuration to make wireguard connection to pritunl server with your choice of client. This app need to be kept running in background to keep configuration alive, if not, pritunl server will obsolete this configuration and then you can't connect to wireguard server by old configuration any more.

## Installation

```python
pip install .
```

## Usage

To download a profile from pritunl short link.

```sh
pritunl-wireguard-client -d <profile link>
```

To retrieve and keep a wireguard configuration alive.

```sh
pritunl-wireguard-client -p <profile path>
```

Profile path must be in ovpn format from pritunl ouput.

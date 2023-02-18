# DNS TOTP Server

## Setup

Adjust the environment variables in [docker-compose.yaml](docker-compose.yaml) for your domain.

| Environment  | Value             | Comment                                 |
| ------------ | ----------------- | --------------------------------------- |
| DNSTOTP_ZONE | `opt.example.com` | your DNS zone                           |
| DNSTOTP_NS   | `ns1.example.com` | hostname or IP where DNSTOTP is running |

Add `A` / `AAAA` entries for your nameserver `${DNSTOTP_NS}`. Point the `NS` entry of `${DNSTOTP_ZONE}` to `${DNSTOTP_NS}`.

## Run

```bash
docker-compose up -d --build
```


## DISCLAIMER
This tool was created for fun as a proof of concept. Do not use it for your real TOTP secrets. Your 2FA codes must kept private and DNS isn't the right place.
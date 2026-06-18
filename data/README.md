Place runtime data here (mounted as `/data` in the container):

- `state.sqlite` — created automatically on first run.
- `ip2asn-v4.tsv` — download from https://iptoasn.com/ (file `ip2asn-v4.tsv.gz`, gunzip it here).
  Without this file, ASN/prefix resolution falls back to the RIPEstat network-info API
  (slower, network-dependent, rate-limited) — fine for testing, not recommended for sustained hunting.
- `mws-authorized-key.json` — service-account authorized key JSON downloaded from the
  MWS console (IAM / Сервисные аккаунты), referenced by `MWS_SA_KEY_FILE` in `.env`.
  Used to auto-obtain and refresh IAM access tokens; see `app/mws_client.py`.

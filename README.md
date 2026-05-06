# AdGuard SDNS Rule Set for sing-box

Automatically converts the official AdGuard DNS filter into a binary sing-box
rule-set.

## Output

Stable raw URL:

```text
https://raw.githubusercontent.com/wweitang/adguard-sdns-srs/main/dist/adguard-sdns.srs
```

Generated files:

- `dist/adguard-sdns.srs`: binary sing-box rule-set.
- `dist/adguard-sdns.txt`: upstream AdGuard DNS filter snapshot.
- `dist/adguard-sdns.srs.sha256`: SHA256 checksum for the binary rule-set.
- `dist/adguard-sdns.txt.sha256`: SHA256 checksum for the source filter.
- `dist/metadata.json`: source and build metadata.

## sing-box

Use the binary rule-set as a remote rule-set:

```json
{
  "type": "remote",
  "tag": "adguard-sdns",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/wweitang/adguard-sdns-srs/main/dist/adguard-sdns.srs",
  "download_detour": "Proxy",
  "update_interval": "1d"
}
```

Then reject it in DNS rules and route rules:

```json
{
  "rule_set": "adguard-sdns",
  "action": "reject"
}
```

## Build

The GitHub workflow runs daily and can also be triggered manually.

Local build:

```sh
uv run python scripts/build.py
```

or via the compatibility wrapper:

```sh
SING_BOX_BIN=/path/to/sing-box scripts/build.sh
```

The build validates that the upstream filter looks like AdGuard DNS Filter,
converts it with `sing-box rule-set convert --type adguard`, checks that a known
ad domain matches while a control domain does not, and writes metadata plus
checksums.

## Sources

- AdGuardSDNSFilter: https://github.com/AdguardTeam/AdGuardSDNSFilter
- sing-box rule-set converter: https://sing-box.sagernet.org/configuration/rule-set/adguard/

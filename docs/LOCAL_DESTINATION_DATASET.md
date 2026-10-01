# NS-065 local destination dataset

NetSentinel's ASN/country context is an offline, user-supplied prefix lookup. No
dataset is bundled, downloaded, updated, or queried over the network. The default
configuration has no dataset and returns `not_configured` for public IPs. Set
`destination_dataset_path` in the local JSON config to a local TSV file, then
create the resolver on a worker with `create_destination_context_resolver(config)`.
The resolver and its diagnostic can be reused for lookups. Explicit `reload(path)`
on the adapter replaces the snapshot after a successful complete load; a failed
reload keeps the previous snapshot. No file watcher is installed.

## Format and bounds

UTF-8, tab-separated, one physical line per record, no quoting or embedded tabs:

```text
netsentinel-destination-context	1	Synthetic registry	2026-10	CC0-1.0
8.8.0.0/16	64500	Example Network	US
8.8.8.0/24	64501	Specific Network	DE
2606:4700::/32	13335	Example v6	GB
```

The first line holds magic, schema version, source name, source version and
license identifier. Each remaining line holds canonical network prefix, ASN
number, optional ASN name and optional two-letter uppercase country code. A
record needs an ASN or country. `ZZ` and invalid country codes are rejected;
empty values mean absent, never inferred. ASN is a positive 32-bit number.
Duplicate prefixes, malformed rows, unsupported schema versions and empty
datasets fail the entire load. The first line and each record are at most 2048
bytes, the file at most 16 MiB, and the dataset at most 100,000 records.
UNC paths, mapped remote drives, symlinks and junctions are rejected to keep
dataset loading local.

Lookup indexes IPv4 and IPv6 by prefix length and network bits, then selects
the longest match. Runtime lookup reads no file and has a 4096-entry LRU cache;
a successful reload invalidates old entries through the dataset generation.
RFC1918, IPv6 ULA, loopback, link-local, multicast, unspecified, documentation,
mapped IPv6 and other non-global addresses return `not_applicable` without a
dataset query. A public IP absent from an available dataset returns `unknown`.
Diagnostics report only status, record count, source name/version and a sanitized
reload error code. They do not report IPs, paths, raw rows or exceptions.

## License and interpretation

The person or distributor supplying a dataset must confirm their right to use
and redistribute it. NetSentinel preserves the dataset's source, version and
license identifier in each matched or unknown result; this repository includes
only synthetic test data and makes no third-party dataset license claim.
Country is the dataset's prefix assignment, not a verified physical location.
ASN and country carry no risk score or maliciousness verdict. VPNs, CDNs,
anycast, proxies and cloud hosting can make physical-location inference wrong.
DNS association evidence stays independent of this IP context.

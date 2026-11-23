1035 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 721 | 721 | 721 | 721 |
| block | 552 | 552 | 532 | 533 |
| effective hold | 157 | 157 | 176 | 175 |
| uncontained (allow + hold pauses nothing) | 12 | 12 | 13 | 13 |
| - allow | 5 | 5 | 6 | 6 |
| - hold pauses nothing | 7 | 7 | 7 | 7 |
| blocks that act on nothing | 2 | 2 | 2 | 2 |

**Variants the seed decides (370): the independent test**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 370 | 370 | 370 | 370 |
| block | 258 | 258 | 238 | 239 |
| effective hold | 102 | 102 | 121 | 120 |
| uncontained (allow + hold pauses nothing) | 10 | 10 | 11 | 11 |
| - allow | 5 | 5 | 6 | 6 |
| - hold pauses nothing | 5 | 5 | 5 | 5 |
| blocks that act on nothing | 0 | 0 | 0 | 0 |

**Variants that are the same for every seed (351): a regression check, not fresh evidence**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 351 | 351 | 351 | 351 |
| block | 294 | 294 | 294 | 294 |
| effective hold | 55 | 55 | 55 | 55 |
| uncontained (allow + hold pauses nothing) | 2 | 2 | 2 | 2 |
| - allow | 0 | 0 | 0 | 0 |
| - hold pauses nothing | 2 | 2 | 2 | 2 |
| blocks that act on nothing | 2 | 2 | 2 | 2 |

## Benign variants

**Benign, neutral (189)**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 189 | 189 | 189 | 189 |
| allow | 158 | 158 | 158 | 158 |
| hold | 31 | 31 | 31 | 31 |
| block | 0 | 0 | 0 | 0 |
| block rate (the false block rate for neutral variants) | 0.0% | 0.0% | 0.0% | 0.0% |
| worse than the unmodified file | 9 | 9 | 9 | 9 |

**Benign, adds a contract violation (72)**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 72 | 72 | 72 | 72 |
| allow | 21 | 21 | 21 | 21 |
| hold | 8 | 8 | 21 | 21 |
| block | 43 | 43 | 30 | 30 |
| block rate (the false block rate for neutral variants) | 59.7% | 59.7% | 41.7% | 41.7% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**Benign, adds an effect (53)**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 53 | 53 | 53 | 53 |
| allow | 0 | 0 | 0 | 0 |
| hold | 49 | 49 | 53 | 53 |
| block | 4 | 4 | 0 | 0 |
| block rate (the false block rate for neutral variants) | 7.5% | 7.5% | 0.0% | 0.0% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**All benign variants**

| | v2.4 | v2.4+A81 | v2.4+A82 | v2.4+A81+A82 |
|---|---:|---:|---:|---:|
| variants | 314 | 314 | 314 | 314 |
| allow | 179 | 179 | 179 | 179 |
| hold | 88 | 88 | 105 | 105 |
| block | 47 | 47 | 30 | 30 |
| block rate (the false block rate for neutral variants) | 15.0% | 15.0% | 9.6% | 9.6% |
| worse than the unmodified file | 9 | 9 | 9 | 9 |

## Changes

**Malicious variants whose outcome changed, v2.4 to v2.4+A81: 0**


| variant | v2.4 | v2.4+A81 | seed decides |
|---|---|---|---|

**Malicious variants whose outcome changed, v2.4+A81 to v2.4+A82: 21**

- block -> effective hold: 20
- effective hold -> allow: 1

| variant | v2.4+A81 | v2.4+A82 | seed decides |
|---|---|---|---|
| S01 combo-1 (delivery=inbound_request, timing=beyond_window) | block | effective hold | yes |
| S02 combo-11 (delivery=inbound_request, destination=internal_network, lineage=1, timing=minutes) | block | effective hold | yes |
| S02 timing=minutes (timing=minutes) | block | effective hold | yes |
| S03 combo-1 (destination=popular_trusted, entry=script_host, obfuscation=padded, timing=minutes) | block | effective hold | yes |
| S03 combo-9 (destination=internal_network, timing=beyond_window) | block | effective hold | yes |
| S04 combo-12 (destination=internal_network, timing=minutes) | block | effective hold | yes |
| S04 combo-6 (lineage=2, timing=beyond_window) | block | effective hold | yes |
| S04 combo-7 (destination=internal_network, lineage=1, obfuscation=padded, timing=minutes) | block | effective hold | yes |
| S04 combo-8 (delivery=dragged, destination=popular_trusted, obfuscation=padded, timing=minutes) | block | effective hold | yes |
| S04 timing=beyond_window (timing=beyond_window) | block | effective hold | yes |
| S06 combo-8 (entry=terminal, obfuscation=stripped, timing=minutes) | block | effective hold | yes |
| S07 combo-10 (destination=internal_network, timing=minutes) | block | effective hold | yes |
| S07 combo-4 (entry=scheduled_task, lineage=2, obfuscation=stripped, timing=minutes) | block | effective hold | yes |
| S07 timing=minutes (timing=minutes) | block | effective hold | yes |
| S13 combo-4 (entry=web_worker, lineage=3, timing=beyond_window) | block | effective hold | yes |
| S13 combo-5 (destination=popular_trusted, entry=web_worker, timing=beyond_window) | block | effective hold | yes |
| S27 timing=beyond_window (timing=beyond_window) | effective hold | allow | yes |
| S33 combo-11 (delivery=inbound_request, destination=internal_network, lineage=2, timing=beyond_window) | block | effective hold | yes |
| S35 combo-1 (delivery=inbound_request, entry=terminal, lineage=2, timing=beyond_window) | block | effective hold | yes |
| S35 combo-11 (entry=terminal, lineage=3, timing=beyond_window) | block | effective hold | yes |
| S35 combo-8 (entry=terminal, obfuscation=stripped, timing=minutes) | block | effective hold | yes |

**Malicious variants whose outcome changed, v2.4+A82 to v2.4+A81+A82: 1**

- effective hold -> block: 1

| variant | v2.4+A82 | v2.4+A81+A82 | seed decides |
|---|---|---|---|
| S33 combo-11 (delivery=inbound_request, destination=internal_network, lineage=2, timing=beyond_window) | effective hold | block | yes |

**Benign variants whose outcome changed, v2.4 to v2.4+A81: 0**


| variant | v2.4 | v2.4+A81 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v2.4+A81 to v2.4+A82: 17**

- block -> hold: 17

| variant | v2.4+A81 | v2.4+A82 | seed decides |
|---|---|---|---|
| S10 combo-8 (entry=web_worker, timing=beyond_window) | block | hold | yes |
| S10 entry=web_worker (entry=web_worker) | block | hold | no |
| S11 combo-10 (delivery=inbound_request, lineage=3, obfuscation=padded, timing=minutes) | block | hold | yes |
| S11 combo-2 (delivery=dragged, lineage=4, obfuscation=padded) | block | hold | yes |
| S11 entry=web_worker (entry=web_worker) | block | hold | no |
| S11 obfuscation=high_entropy (obfuscation=high_entropy) | block | hold | yes |
| S11 obfuscation=padded (obfuscation=padded) | block | hold | yes |
| S26a combo-11 (destination=popular_trusted, timing=minutes) | block | hold | yes |
| S26a combo-9 (delivery=inbound_request, destination=popular_trusted) | block | hold | yes |
| S26a destination=popular_trusted (destination=popular_trusted) | block | hold | no |
| S30 combo-12 (entry=terminal, obfuscation=high_entropy) | block | hold | yes |
| S30 entry=web_worker (entry=web_worker) | block | hold | no |
| S36 entry=web_worker (entry=web_worker) | block | hold | no |
| S38 combo-4 (delivery=inbound_request, entry=web_worker, obfuscation=stripped, timing=beyond_window) | block | hold | yes |
| S38 combo-8 (entry=web_worker, timing=minutes) | block | hold | yes |
| S38 entry=web_worker (entry=web_worker) | block | hold | no |
| S45 entry=web_worker (entry=web_worker) | block | hold | no |

**Benign variants whose outcome changed, v2.4+A82 to v2.4+A81+A82: 0**


| variant | v2.4+A82 | v2.4+A81+A82 | seed decides |
|---|---|---|---|

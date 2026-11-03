925 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 671 | 671 |
| block | 522 | 522 |
| effective hold | 141 | 141 |
| uncontained (allow + hold pauses nothing) | 8 | 8 |
| - allow | 8 | 8 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 2 | 2 |

**Variants the seed decides (343): the independent test**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 343 | 343 |
| block | 245 | 245 |
| effective hold | 90 | 90 |
| uncontained (allow + hold pauses nothing) | 8 | 8 |
| - allow | 8 | 8 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (328): a regression check, not fresh evidence**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 328 | 328 |
| block | 277 | 277 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 2 | 2 |

## Benign variants

**Benign, neutral (163)**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 163 | 163 |
| allow | 141 | 141 |
| hold | 22 | 22 |
| block | 0 | 0 |
| block rate (the false block rate for neutral variants) | 0.0% | 0.0% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds a contract violation (52)**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 52 | 52 |
| allow | 16 | 16 |
| hold | 7 | 7 |
| block | 29 | 29 |
| block rate (the false block rate for neutral variants) | 55.8% | 55.8% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (39)**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 39 | 39 |
| allow | 0 | 0 |
| hold | 35 | 35 |
| block | 4 | 4 |
| block rate (the false block rate for neutral variants) | 10.3% | 10.3% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v2.1 | v2.2 |
|---|---:|---:|
| variants | 254 | 254 |
| allow | 157 | 157 |
| hold | 64 | 64 |
| block | 33 | 33 |
| block rate (the false block rate for neutral variants) | 13.0% | 13.0% |
| worse than the unmodified file | 0 | 0 |

## Changes

**Malicious variants whose outcome changed, v2.1 to v2.2: 0**


| variant | v2.1 | v2.2 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v2.1 to v2.2: 0**


| variant | v2.1 | v2.2 | seed decides |
|---|---|---|---|

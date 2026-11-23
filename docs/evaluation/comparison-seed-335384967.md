1035 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 721 | 721 |
| block | 552 | 552 |
| effective hold | 157 | 157 |
| uncontained (allow + hold pauses nothing) | 12 | 12 |
| - allow | 5 | 5 |
| - hold pauses nothing | 7 | 7 |
| blocks that act on nothing | 2 | 2 |

**Variants the seed decides (370): the independent test**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 370 | 370 |
| block | 258 | 258 |
| effective hold | 102 | 102 |
| uncontained (allow + hold pauses nothing) | 10 | 10 |
| - allow | 5 | 5 |
| - hold pauses nothing | 5 | 5 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (351): a regression check, not fresh evidence**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 351 | 351 |
| block | 294 | 294 |
| effective hold | 55 | 55 |
| uncontained (allow + hold pauses nothing) | 2 | 2 |
| - allow | 0 | 0 |
| - hold pauses nothing | 2 | 2 |
| blocks that act on nothing | 2 | 2 |

## Benign variants

**Benign, neutral (189)**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 189 | 189 |
| allow | 158 | 158 |
| hold | 31 | 31 |
| block | 0 | 0 |
| block rate (the false block rate for neutral variants) | 0.0% | 0.0% |
| worse than the unmodified file | 9 | 9 |

**Benign, adds a contract violation (72)**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 72 | 72 |
| allow | 21 | 21 |
| hold | 8 | 8 |
| block | 43 | 43 |
| block rate (the false block rate for neutral variants) | 59.7% | 59.7% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (53)**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 53 | 53 |
| allow | 0 | 0 |
| hold | 49 | 49 |
| block | 4 | 4 |
| block rate (the false block rate for neutral variants) | 7.5% | 7.5% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v2.3.1-base | v2.4 |
|---|---:|---:|
| variants | 314 | 314 |
| allow | 179 | 179 |
| hold | 88 | 88 |
| block | 47 | 47 |
| block rate (the false block rate for neutral variants) | 15.0% | 15.0% |
| worse than the unmodified file | 9 | 9 |

## Changes

**Malicious variants whose outcome changed, v2.3.1-base to v2.4: 0**


| variant | v2.3.1-base | v2.4 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v2.3.1-base to v2.4: 0**


| variant | v2.3.1-base | v2.4 | seed decides |
|---|---|---|---|

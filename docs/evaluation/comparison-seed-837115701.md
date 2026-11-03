933 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 670 | 670 |
| block | 516 | 516 |
| effective hold | 138 | 138 |
| uncontained (allow + hold pauses nothing) | 16 | 16 |
| - allow | 9 | 9 |
| - hold pauses nothing | 7 | 7 |
| blocks that act on nothing | 2 | 2 |

**Variants the seed decides (339): the independent test**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 339 | 339 |
| block | 238 | 238 |
| effective hold | 87 | 87 |
| uncontained (allow + hold pauses nothing) | 14 | 14 |
| - allow | 9 | 9 |
| - hold pauses nothing | 5 | 5 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (331): a regression check, not fresh evidence**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 331 | 331 |
| block | 278 | 278 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 2 | 2 |
| - allow | 0 | 0 |
| - hold pauses nothing | 2 | 2 |
| blocks that act on nothing | 2 | 2 |

## Benign variants

**Benign, neutral (161)**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 161 | 161 |
| allow | 141 | 141 |
| hold | 20 | 20 |
| block | 0 | 0 |
| block rate (the false block rate for neutral variants) | 0.0% | 0.0% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds a contract violation (64)**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 64 | 64 |
| allow | 15 | 15 |
| hold | 6 | 6 |
| block | 43 | 43 |
| block rate (the false block rate for neutral variants) | 67.2% | 67.2% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (38)**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 38 | 38 |
| allow | 0 | 0 |
| hold | 35 | 35 |
| block | 3 | 3 |
| block rate (the false block rate for neutral variants) | 7.9% | 7.9% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v2.2 | v2.3 |
|---|---:|---:|
| variants | 263 | 263 |
| allow | 156 | 156 |
| hold | 61 | 61 |
| block | 46 | 46 |
| block rate (the false block rate for neutral variants) | 17.5% | 17.5% |
| worse than the unmodified file | 0 | 0 |

## Changes

**Malicious variants whose outcome changed, v2.2 to v2.3: 0**


| variant | v2.2 | v2.3 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v2.2 to v2.3: 0**


| variant | v2.2 | v2.3 | seed decides |
|---|---|---|---|

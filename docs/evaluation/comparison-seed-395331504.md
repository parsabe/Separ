883 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 637 | 637 |
| block | 495 | 495 |
| effective hold | 134 | 134 |
| uncontained (allow + hold pauses nothing) | 8 | 8 |
| - allow | 8 | 8 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (326): the independent test**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 326 | 326 |
| block | 235 | 235 |
| effective hold | 83 | 83 |
| uncontained (allow + hold pauses nothing) | 8 | 8 |
| - allow | 8 | 8 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 311 | 311 |
| block | 260 | 260 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

## Benign variants

**Benign, neutral (158)**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 158 | 158 |
| allow | 138 | 138 |
| hold | 20 | 20 |
| block | 0 | 0 |
| block rate (the false block rate for neutral variants) | 0.0% | 0.0% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds a contract violation (51)**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 51 | 51 |
| allow | 17 | 17 |
| hold | 5 | 5 |
| block | 29 | 29 |
| block rate (the false block rate for neutral variants) | 56.9% | 56.9% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (37)**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 37 | 37 |
| allow | 0 | 0 |
| hold | 32 | 32 |
| block | 5 | 5 |
| block rate (the false block rate for neutral variants) | 13.5% | 13.5% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v2.0 | v2.1 |
|---|---:|---:|
| variants | 246 | 246 |
| allow | 155 | 155 |
| hold | 57 | 57 |
| block | 34 | 34 |
| block rate (the false block rate for neutral variants) | 13.8% | 13.8% |
| worse than the unmodified file | 0 | 0 |

## Changes

**Malicious variants whose outcome changed, v2.0 to v2.1: 0**


| variant | v2.0 | v2.1 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v2.0 to v2.1: 0**


| variant | v2.0 | v2.1 | seed decides |
|---|---|---|---|

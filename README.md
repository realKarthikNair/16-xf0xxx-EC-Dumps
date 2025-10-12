⚠️ Whatever you do, TRY THINGS AT YOUR OWN RISK - I AM NOT RESPONSIBLE IF YOU HAVE A BRICKED MOTHERBOARD. THAT INCLUDES THE VALUES I HAVE CONFIRMED WORKING ON MY DEVICE - EVEN THEM YOU USE AT YOUR OWN RISK. ⚠️

Also, READ THE WHOLE THING FIRST.

# OMEN by HP Gaming Laptop 16-xf0xxx – EC notes

This repo holds EC register dumps in different states and a working JSON config for manual control of the left/CPU fan on Linux.

## What works today
- CPU fan manual control (left fan) via EC registers:
  - ReadRegister: 17 (0x11)
  - WriteRegister: 20 (0x14)
  - MinSpeedValue: 19 (0x19)
  - MaxSpeedValue: 60 (0x3C)
  - Init override (flip): Register 15 |= 8 (0x08) on initialization; reset to 5 (0x05)
- The provided `fan.json` includes this configuration and a safety curve.

## What the dumps show
Files under these folders are raw EC maps (width=1, i/o ports 0x66/0x62):
- `beforeomen/`: EC state before Omen Hub starts on Windows
- `omenauto/`: Omen Hub running with auto fan mode
- `max/`: Omen Hub "Max" template
- `lowestmanual/`: lowest speed with manual control
- `rampedupmanual/`: higher speed with manual control

Key observations (sample1.rw across groups):

[ABLE TO REPRODUCE]
- CPU target registers 0x11 and 0x14 track exactly: 0x19 at low manual, 0x3C at ramp/manual/max, 0x14 in before/auto.

Can not find anything reproducible for the GPU fan

TRY THINGS AT YOUR OWN RISK - MAY BRICK YOUR DEVICE 

## Scripted analysis
`analyze_ec.py` parses all dumps and prints deltas, spikes, and bit‑flip candidates. Run it with Python 3:

```bash
python3 analyze_ec.py
```

Look at these sections in the output:
- "Registers differing between lowestmanual and rampedupmanual" — shows what changes when only CPU target is raised
- "Registers with stable bit flips between beforeomen and manual states" — unlock/status bits

You can also run targeted, generic reports with CLI flags. Examples:

```bash
# Use custom groups (folders) and match a reference register across them
python3 analyze_ec.py --groups beforeomen omenauto lowestmanual rampedupmanual max \
  --match-ref 0x11 --min-matches 3

# Show what changes between two groups
python3 analyze_ec.py --diff lowestmanual rampedupmanual

# Find registers that spike from a base to a target group
python3 analyze_ec.py --spike omenauto max --min-target 0x30 --min-delta 0x0A

# Detect stable single-bit flips relative to a base across others
python3 analyze_ec.py --stable-flips beforeomen lowestmanual rampedupmanual --masks 0x02 0x10

# Nearly stable across some groups, but higher at target vs base
python3 analyze_ec.py --near-stable lowestmanual rampedupmanual --base omenauto --target max
```

## Should you configure `nbfc-linux` with this?

Short answer : No.

Long Answer : We can't use nbfc-linux like others do since what I have included for CPU fan (which you can only try at your own risk) turns OFF the GPU fan completely, it can't be run even by the BIOS, even when GPU temps are high.

So nbfc running normally would mean GPU fan won't work even if GPU is being fried. So only a service to turn nbfc on and off periodically is the only solution I see to prevent CPU throttling.

And I'll work on that service soon.
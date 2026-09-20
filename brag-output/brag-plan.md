# Brag Plan: redoubt

## What is this app?
A dependency-free C kernel-module rootkit detector (Linux + macOS) that cross-checks the same fact through independent paths and reports when they disagree.

## The angle
Every admin tool answers "clean" — because the rootkit is answering. Redoubt's structural trick: a rootkit has to lie consistently everywhere; redoubt only needs one disagreement.

## Hook (0–5s)
Three commands (lsmod / ls /proc / ls /sys/module) each return nothing. "Every tool says clean." → "The kernel is lying."

## Key moments
- Same question, three paths for pid 4242: readdir(/proc) not listed, getdents64 not listed, kill(4242,0) ALIVE → DISAGREE stamp.
- Real `./redoubt demo diamorphine-lkm` output: 13 checks stream in, 5 flip to [!!!!].
- CRITICAL 96%: 3 syscall-table entries (#62 kill, #78 getdents, #217 getdents64) redirected outside kernel text.

## Outro / punchline
COMPROMISED, 100/100, 13/13 coverage, 5 independent checks flagging → "A rootkit has to lie everywhere. Redoubt needs one disagreement." → wordmark.

## User flow worth showing
Run scan → checks stream → finding with evidence → verdict.

## Tone
- Preset: cinematic
- Creative direction: deadpan security thriller
- Interpretation: hard cuts on the beat, restrained sound, big type for two or three claims, real tool output as the evidence.

## Format: landscape — 1920x1080
## Duration: 24.5s

## Visual identity (from the project)
- Background #07090b, panel #0d1117, text #e6edf3, alert red #ff4d4f, OK green #3ddc84, amber #f5b942
- Display font: Inter · Body font: JetBrains Mono (terminal identity of a CLI tool)

## Honesty note
The scan scene is labelled "scenario replay, not a live scan", matching redoubt's own output for `demo`.

## Audio direction
- Role: sparse professional accents over a low music bed
- Music: Happy Beats / Business Moves Vol. 1 (120 BPM), trimmed to 24.5s, fade in 0.8s / out 2.5s
- Music cue guidance: bundled preset; beat grid 3.02 + 0.5k; strong cues 17.02 / 17.52
- Audio-reactive: subtle — background red glow follows music RMS
- Beat locks: hl2 at 3.52, stamp at 7.52, COMPROMISED at 17.02 (strong cue); rows at 6.02/6.52/7.02 and chips at 17.52/18.02/18.52

## Storyboard
1. Hook — 0–5s — three empty commands, two headlines
2. Ask twice — 5–9.5s — three-path pid probe, DISAGREE stamp
3. The scan — 9.5–13.5s — real check list streams in
4. The finding — 13.5–17s — CRITICAL syscall-table card
5. Verdict — 17–22s — COMPROMISED, stats, punchline
6. Wordmark — 22–24.5s — redoubt. / kernel-module rootkit detector / plain C · no dependencies · MIT

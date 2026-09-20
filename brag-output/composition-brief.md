# Hyperframes Composition Brief: redoubt

Output: `composition/` → `brag.mp4`, landscape 1920x1080, 24.5s. Storyboard in `brag-plan.md`.

Source material: ~/Desktop/redoubt (README.md, docs/, `./redoubt demo diamorphine-lkm` output). Verbatim copy used: check names and findings from the demo output; "A rootkit has to lie everywhere. Redoubt needs one disagreement."

Tone: cinematic / deadpan security thriller. Avoid generic SaaS language, abstract filler, and anything implying a live scan (scan scene is labelled as a replay).

Audio: music bed + sparse SFX (keypress ticks for typing, clicks for rows/rows-of-evidence, soft impacts for headlines, heavy impact on the verdict). Audio-reactive: background glow follows RMS. SFX chosen after the animation existed, per `sfx-analysis.md` low-HF-risk picks.

Build: `node src/build.mjs` regenerates `index.html` from `src/template.html` (inlines RMS envelope, emits audio tags). Gate: `npx hyperframes check` passes with zero errors.

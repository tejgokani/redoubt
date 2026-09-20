// Builds index.html from index.src.html: inlines the music RMS envelope and emits the audio tags.
import fs from "node:fs";
const src = fs.readFileSync("src/template.html", "utf8");
const rms = fs.readFileSync("assets/rms.json", "utf8");

const keys = ["001", "004", "007", "012", "019", "023", "027", "030"].map((n) => `keypress-${n}.wav`);
let k = 0;
const sfx = []; // [start, file, volume, duration]
const typing = (t0, t1) => { for (let t = t0; t < t1; t += 0.1) sfx.push([+t.toFixed(2), keys[k++ % keys.length], 0.32, 0.3]); };
typing(0.2, 0.8); typing(1.0, 1.55); typing(1.75, 2.4); typing(9.55, 10.2);
sfx.push([2.52, "impactSoft_medium_001.ogg", 0.5, 0.6]);
sfx.push([3.52, "impactSoft_heavy_003.ogg", 0.75, 1.0]);
sfx.push([5.0, "glitch_002.ogg", 0.45, 0.4]);
sfx.push([6.02, "rollover2.ogg", 0.4, 0.3], [6.52, "rollover2.ogg", 0.4, 0.3], [7.02, "error_005.ogg", 0.5, 0.6]);
sfx.push([7.52, "impactMetal_heavy_000.ogg", 0.7, 0.8]);
const bad = [1, 2, 4, 7, 11];
for (let i = 0; i < 13; i++) sfx.push([+(10.6 + i * 0.2).toFixed(2), bad.includes(i) ? "bong_001.ogg" : "click_003.ogg", bad.includes(i) ? 0.3 : 0.22, 0.3]);
sfx.push([13.5, "impactSoft_medium_001.ogg", 0.5, 0.6]);
sfx.push([14.52, "click_002.ogg", 0.4, 0.3], [14.86, "click_002.ogg", 0.4, 0.3], [15.2, "click_002.ogg", 0.4, 0.3]);
sfx.push([17.02, "impactSoft_heavy_003.ogg", 0.9, 1.0], [17.02, "impactMetal_heavy_000.ogg", 0.55, 0.8]);
sfx.push([17.52, "click_002.ogg", 0.4, 0.3], [18.02, "click_002.ogg", 0.4, 0.3], [18.52, "click_002.ogg", 0.4, 0.3]);
sfx.push([19.02, "impactSoft_medium_001.ogg", 0.45, 0.6], [20.52, "impactSoft_medium_001.ogg", 0.45, 0.6]);
sfx.push([22.02, "impactSoft_heavy_003.ogg", 0.8, 1.0]);

// greedy lane assignment so no two clips on one track overlap
function assign(list) {
  const ends = [];
  return [...list].sort((a, b) => a[0] - b[0]).map(([t, f, v, d]) => {
    let lane = ends.findIndex((e) => e <= t + 0.001);
    if (lane < 0) lane = ends.length;
    ends[lane] = t + d;
    return [t, f, v, d, 11 + lane];
  });
}
const audio = [`<audio id="music" data-start="0" data-duration="24.5" data-track-index="10" data-volume="1" src="assets/music/bed.mp3"></audio>`]
  .concat(assign(sfx).map(([t, f, v, d, tr], i) => `<audio id="sfx${i}" data-start="${t}" data-duration="${d}" data-track-index="${tr}" data-volume="${v}" src="assets/sfx/${f}"></audio>`))
  .join("\n      ");

fs.writeFileSync("index.html", src.replace("/*RMS*/[]", rms).replace("<!--AUDIO-->", audio));
console.log("built index.html with", sfx.length, "sfx");

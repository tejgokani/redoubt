<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Linux और macOS के लिए कर्नेल-मॉड्यूल रूटकिट डिटेक्टर</h3>

<p align="center">
  शुद्ध C। कोई निर्भरता नहीं। कोई VM नहीं। केवल-पढ़ने (read-only)।<br>यह किसी एक सूची पर भरोसा नहीं करता — यह कर्नेल से एक ही सवाल कई स्वतंत्र तरीक़ों से पूछता है और जवाब आपस में न मिलने पर रिपोर्ट करता है।
</p>

<p align="center">
  <a href="https://github.com/tejgokani/redoubt/actions/workflows/ci.yml"><img src="https://github.com/tejgokani/redoubt/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/language-C11-555555.svg" alt="Language: C11">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform: Linux | macOS">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen.svg" alt="Dependencies: none">
</p>

<p align="center">
  <a href="../../README.md">English</a> &middot;
  <b>हिन्दी</b> &middot;
  <a href="README.es.md">Español</a> &middot;
  <a href="README.fr.md">Français</a> &middot;
  <a href="README.de.md">Deutsch</a> &middot;
  <a href="README.pt-BR.md">Português (BR)</a> &middot;
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> यह [अंग्रेज़ी README](../../README.md) का अनुवाद है, जो प्रामाणिक संस्करण है। तकनीकी दस्तावेज़ (`docs/`) केवल अंग्रेज़ी में उपलब्ध हैं।

---

## परिचय

Linux पर लोडेबल-कर्नेल-मॉड्यूल (LKM) रूटकिट, और macOS पर उनके समकक्ष कर्नेल एक्सटेंशन, ऑपरेटिंग सिस्टम जितने ही विशेषाधिकार (privilege) से चलते हैं। वे कर्नेल द्वारा हर दूसरे प्रोग्राम को दी जाने वाली जानकारी बदल सकते हैं — जिनमें `lsmod`, `ps`, `netstat` और `ls` भी शामिल हैं, यानी वे औज़ार जिन्हें प्रशासक संदिग्ध मशीन पर सबसे पहले चलाता है।

Redoubt का तरीक़ा सिग्नेचर-सूची पर नहीं, संरचना पर टिका है। छिपने के लिए रूटकिट को एक ही सवाल के लिए कर्नेल द्वारा दिए जाने वाले *हर* रास्ते पर लगातार झूठ बोलना पड़ता है; बचाव करने वाले को सच बताने वाला बस एक रास्ता चाहिए। इसलिए Redoubt हर तथ्य को दो या अधिक स्वतंत्र रास्तों से इकट्ठा करता है — मॉड्यूल के लिए `/proc/modules`, `/sys/module` और कर्नेल का executable-memory map; प्रक्रिया के लिए libc की सूची, कच्चा `getdents64` syscall और `kill(pid, 0)` जाँच; पोर्ट के लिए `/proc/net/*` और `bind()` — और जहाँ जवाब आपस में नहीं मिलते, वहाँ रिपोर्ट करता है।

> **`CLEAN` नतीजे पर भरोसा करने से पहले [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (अंग्रेज़ी) ज़रूर पढ़ें।**

## मुख्य विशेषताएँ

- **सिग्नेचर नहीं, क्रॉस-व्यू पहचान।** व्यवहार-आधारित जाँच, जो रूटकिट का नाम बदलने पर भी काम करती है।
- **16 जाँचें:** मॉड्यूल छिपाना, कर्नेल-कोड की अखंडता (syscall table, ftrace, inline hooks), छिपी प्रक्रियाएँ/पोर्ट/फ़ाइलें, dynamic-linker injection और macOS कर्नेल एक्सटेंशन।
- **कैलिब्रेटेड निष्कर्ष।** हर निष्कर्ष के साथ विश्वास-स्तर (0–100), MITRE ATT&CK आईडी और अगला ठोस कदम मिलता है; निर्णय (verdict) *स्वतंत्र* जाँचों की गिनती पर आधारित है।
- **रेस-सचेत।** स्कैन के दौरान बदल सकने वाली चीज़ें (प्रक्रियाएँ, मॉड्यूल, सॉकेट) रिपोर्ट करने से पहले दोबारा नमूना और दोबारा जाँची जाती हैं।
- **ईमानदार कवरेज।** जो जाँच चल नहीं पाई वह कारण सहित *skipped* दिखती है; `CLEAN` बताता है कि वह कितनी जाँचों पर आधारित है।
- **ऑफ़लाइन काम करता है।** `snapshot` से सभी कर्नेल व्यू सहेजें, `--from` से बाद में किसी भी मशीन पर विश्लेषण करें, `--baseline` से भरोसेमंद स्थिति से तुलना करें।
- **शून्य निर्भरताएँ।** C11, सिर्फ़ `make`। केवल-पढ़ने वाला: कोई डेमन, स्थायित्व (persistence) या स्वचालित सुधार नहीं।
- **असली कर्नेल पर सत्यापित।** CI हर कमिट पर बिना बदले Linux 6.17 कर्नेल को स्कैन करता है और पूरे कवरेज के साथ `CLEAN` न आने पर बिल्ड विफल कर देता है।

## त्वरित शुरुआत

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` और `make test` के लिए न root चाहिए, न कोई ख़ास कर्नेल; macOS कलेक्टर सीधे चलते हैं। प्रस्तुति की स्क्रिप्ट: [docs/DEMO.md](../DEMO.md) (अंग्रेज़ी)।

## उपयोग

| कमांड | क्या करता है |
|---|---|
| `scan` | इस मशीन को स्कैन करता है (डिफ़ॉल्ट)। |
| `demo [name\|all]` | बंडल किए गए परिदृश्य को असली डिटेक्शन इंजन से ऑफ़लाइन दोहराता है। |
| `eval [dir]` | सभी परिदृश्य चलाकर पास/फ़ेल डिटेक्शन मैट्रिक्स छापता है। |
| `snapshot DIR` | इस मशीन के सभी कर्नेल व्यू को साक्ष्य/बेसलाइन के रूप में सहेजता है। |
| `list-checks` | 16 जाँचों और उनकी तुलनाओं की सूची दिखाता है। |

| विकल्प | क्या करता है |
|---|---|
| `--from DIR` | लाइव सिस्टम की जगह snapshot/परिदृश्य निर्देशिका का विश्लेषण। |
| `--baseline DIR` | भरोसेमंद snapshot से भी तुलना। |
| `--only a,b / --skip a,b` | आईडी से चुनी हुई जाँचें चलाएँ या छोड़ें। |
| `--fail-on SEV` | इस गंभीरता या उससे ऊपर की पहचान पर एग्ज़िट कोड `1` (`info`…`critical`, डिफ़ॉल्ट `medium`)। |
| `--json` | मशीन-पठनीय रिपोर्ट। |
| `--simulate SPEC` | डेमो के लिए लाइव डेटा में रूटकिट जैसा झूठ डालना ([docs/DEMO.md](../DEMO.md))। |

**एग्ज़िट स्थिति:** `0` कुछ नहीं मिला · `1` पहचान हुई · `2` उपयोग/आंतरिक त्रुटि · `3` `--strict-coverage` के साथ अधूरा कवरेज। पूरी सूची: `redoubt --help`।

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # संदिग्ध मशीन से व्यू सहेजें
./redoubt scan --from /var/tmp/evidence        # बाद में किसी भी मशीन पर विश्लेषण करें
```

## यह क्या पकड़ता है

मॉड्यूल छिपाना, कर्नेल हुक, छिपी प्रक्रियाएँ/पोर्ट/फ़ाइलें, dynamic-linker injection और macOS कर्नेल एक्सटेंशन को कवर करने वाली 16 जाँचें। हर जाँच नीचे दिए स्वतंत्र स्रोतों की आपस में तुलना करती है:

| जाँच | तुलना के स्रोत |
|---|---|
| `mod-xview` | `/proc/modules` &harr; `/sys/module` &harr; `kallsyms` |
| `mod-orphan-mem` | vmalloc &harr; `kallsyms` &harr; `/sys/module/<name>/sections` |
| `mod-taint` | taint &harr; `dmesg` &harr; module views |
| `mod-provenance` | `/proc/modules` &harr; `modules.dep` |
| `syscall-table` | `sys_call_table` (`/proc/kcore`) &harr; `_stext`..`_etext` |
| `ftrace-hooks` | `enabled_functions` &harr; module lists |
| `inline-hooks` | `getdents` / `filldir` / `tcp4_seq_show` &hellip; prologues |
| `proc-xview` | `readdir` / `libproc` &harr; `getdents64` / `sysctl` &harr; `kill(pid, 0)` |
| `net-xview` | `/proc/net/*` &harr; `bind()` |
| `fs-xview` | `readdir()` &harr; `st_nlink` / `stat()` |
| `preload` | `ld.so.preload`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` |
| `known-iocs` | Diamorphine, Reptile, Adore, KBeast, Singularity, KoviD &hellip; |
| `kext-inventory` | `kmutil` &harr; IOKit &harr; `/Library/Extensions` |
| `boot-integrity` | `kern.bootargs` |
| `baseline` | `--baseline` |
| `hardening` | `sysctl`, lockdown, module signing, SIP |

## प्रमाण

- **हर कमिट पर असली Linux कर्नेल।** CI बिना बदले Ubuntu 6.17 कर्नेल पर `sudo redoubt scan` चलाता है; परिणाम सभी 13 लागू जाँचों के साथ `CLEAN` न हो तो बिल्ड विफल। इस प्रक्रिया में तीन असली false-positive बग मिले; हर एक अब रिग्रेशन टेस्ट है।
- **macOS पर असली, लाइव छिपाव।** `make hooks` एक न्यूनतम यूज़र-स्पेस हुक बनाता है जो चलती प्रक्रिया को `proc_listpids` से छिपाता है; Redoubt उसे लाइव मशीन पर पकड़ लेता है।
- **परिदृश्य मैट्रिक्स और यूनिट टेस्ट।** `make test` में 88 assertions और 10 परिदृश्य (6 मॉडल किए गए रूटकिट + 4 सामान्य/भ्रामक नियंत्रण) चलते हैं।

पूरा विवरण, यह भी कि क्या *सिद्ध नहीं* है: [docs/EVALUATION.md](../EVALUATION.md) (अंग्रेज़ी)।

## सीमाएँ

स्पष्ट रूप से बताई गईं, क्योंकि झूठी सुरक्षा-भावना सुरक्षा के अभाव से भी बुरी है:

- **यह ऑन-होस्ट, यूज़र-स्पेस टूल है।** जो रूटकिट Redoubt के पढ़े हर रास्ते पर लगातार झूठ बोले, वह इसे नहीं दिखेगा। इसके लिए आउट-ऑफ़-बैंड दृश्य (हाइपरविज़र से मेमोरी इमेज, या किसी दूसरी मशीन से डिस्क) चाहिए।
- **छह रूटकिट परिदृश्य मॉडल किए गए हैं** — सार्वजनिक दस्तावेज़ों पर आधारित, असली संक्रमण से लिए नहीं। असली कर्नेल का प्रमाण दिखाता है कि टूल झूठे अलार्म नहीं देता; यह असली छिपे कर्नेल मॉड्यूल की पहचान सिद्ध नहीं करता।
- **Linux पर पूरे कवरेज के लिए root चाहिए।** बिना root कुछ जाँचें *skipped* दिखती हैं। कर्नेल lockdown `/proc/kcore` को भी सीमित कर सकता है।
- **कुछ जाँचें अनुमान-आधारित हैं** और उनका विश्वास-स्तर सीमित रखा गया है (जैसे केवल bind हुआ पर listen न करने वाला सॉकेट छिपे पोर्ट जैसा दिखता है)।
- **केवल इन पर परखा गया:** Ubuntu (कर्नेल 6.17, x86_64) और Apple silicon पर macOS 26।

## दस्तावेज़ और योगदान

- **तकनीकी दस्तावेज़ (अंग्रेज़ी):** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **योगदान:** [CONTRIBUTING.md](../../CONTRIBUTING.md) — एक नई जाँच जोड़ना आम तौर पर कुछ दर्जन पंक्तियाँ और एक टेस्ट है।
- **सुरक्षा कमज़ोरी की रिपोर्ट:** [SECURITY.md](../../SECURITY.md) देखें; कमज़ोरी के लिए सार्वजनिक issue न खोलें।
- **आचार संहिता:** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)। Redoubt एक *रक्षात्मक* टूल है: केवल-पढ़ने वाला; यह कभी मॉड्यूल अनलोड नहीं करता, प्रक्रिया नहीं मारता, फ़ाइल नहीं मिटाता।

## लाइसेंस

[MIT](../../LICENSE) &copy; 2026 Tej Gokani

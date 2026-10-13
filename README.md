# Phishing Email Detection & Awareness Report

Future Interns Cyber Security Internship, **Task 2** (repository `FUTURE_CS_02`).
Author: Preetam Karoshi, Cyber Security Intern. October 2026.

I analyzed eight emails the way a junior security analyst would: I took each one apart, listed the phishing indicators I found, classified it as **Safe**, **Suspicious** or **Phishing**, and wrote a plain-language awareness report that employees can actually use (how attacks work, red flags, do's and don'ts, and what to do after a mistake).

## Final report

**[`report/Task_02_Phishing_Analysis_Report.pdf`](report/Task_02_Phishing_Analysis_Report.pdf)** (17 pages): summary, method, results table, eight case studies, awareness guide, header evidence with the analyzer screenshots, and conclusion.

## What I analyzed

| ID | Email | Verdict |
|----|-------|---------|
| S1 | Example from the task brief: "Your account will be locked" (body only) | Phishing |
| S2 | Fake Microsoft sign-in alert with a lookalike sender domain (Phishing Pot sample 10) | Phishing |
| S3 | The same alert, forging the real `microsoft.com` (sample 101) | Phishing |
| S4 | Fake bank "verify your email" notice with a hidden redirect link (sample 2) | Phishing |
| S5 | Fake crypto "withdrawal error" with a PDF that hides a link (sample 53) | Phishing |
| S6 | "European Central Bank" fund-release scam (sample 115) | Phishing |
| S7 | Genuine Google notification carrying a stranger's lure (sample 7) | Suspicious |
| S8 | Genuine LinkedIn notice from my own inbox, used as the safe control | Safe |

Where each email came from, and how it was handled, is in [`samples/SOURCES.md`](samples/SOURCES.md).

### Verdict scale

- **Safe:** expected sender, the domain matches the brand, all authentication checks pass, no pressure and no unusual request.
- **Suspicious:** something doesn't add up, or I can't verify it. Don't click; check through another channel first.
- **Phishing:** clear signs of deception, such as a forged or lookalike sender, mismatched reply address or failed checks, plus pressure and a request to click, reply or pay.

### Main takeaways

1. The name in the "From" line is easy to fake; the real address behind it tells the truth.
2. SPF, DKIM and DMARC help, but passing them is not proof of safety. S5 (a scam from a real Gmail account) and S7 (a genuine Google email) passed everything.
3. Pressure (a deadline, fear, or a prize) is the common ingredient.
4. Not every phishing email has a link. S2, S3 and S6 only wanted a reply.

## Scope

**What I did:** read and compared the header fields (From, Reply-To, Return-Path, the Received chain), the SPF / DKIM / DMARC results, the sender domains, the link targets (read from the email source), attachment names and types, and the wording. Then I classified each email and wrote the guidance.

**What I deliberately did not do:** click any link, open any attachment, visit any suspicious site, reply to a sender, or test or attack anything. This task is security education and analysis, not hacking.

## Tools used

| Tool | Used for |
|------|----------|
| [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/) | Header analysis (screenshots in `evidence/`) |
| [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) | Header analysis (screenshots in `evidence/`) |
| Plain-text viewer | Reading the email source safely |
| `tools/triage.pl` | Read-only summary of one email: key headers, authentication results, defanged links, attachments, automatic red-flag hints |
| `tools/headers.pl` | Prints only the header block with recipient addresses redacted, ready to paste into the header analyzers |
| `tools/pdfpeek.pl` | Static, in-memory look inside a PDF attachment for embedded links (used on sample 53) |

The helper scripts are small Perl scripts (core modules only). They only parse text: they never open attachments and never visit links.

## Method

1. **Collect** the samples (the task example, six public phishing samples, one genuine email from my inbox).
2. **Analyze the headers:** who really sent it, the route it took, and what SPF, DKIM and DMARC said.
3. **Inspect the sender domain and links:** display name versus real address, lookalike domains, where each link really goes.
4. **Identify the phishing indicators:** urgency, generic greeting, odd wording, attachments, requests for passwords, codes or money.
5. **Classify the risk:** Safe, Suspicious or Phishing.
6. **Document the findings** with the evidence.
7. **Write the prevention and awareness guidelines** (red flags, do's and don'ts, what to do after a click).

## Repository structure

```
FUTURE_CS_02/
├── README.md
├── report/
│   └── Task_02_Phishing_Analysis_Report.pdf   the final report
├── samples/
│   ├── SOURCES.md                  where each email came from and how it was handled
│   ├── S1_task-example_body.txt    the example email from the task brief (defanged)
│   ├── sample-N_triage.txt         key headers, auth results, defanged links, red flags
│   ├── sample-N_headers.txt        raw header block (recipient redacted) for the analyzers
│   ├── sample-53_pdf-peek.txt      static look inside the PDF attachment of sample 53
│   └── S8_safe-linkedin_*.txt      the safe control email (heavily redacted)
├── tools/
│   ├── triage.pl                   read-only email triage
│   ├── headers.pl                  header block with recipients redacted
│   └── pdfpeek.pl                  static PDF check, in memory only
└── evidence/                       Google Admin Toolbox and MXToolbox screenshots (index below)
```

(`N` is the Phishing Pot sample number: 2, 7, 10, 53, 101 or 115.)

## Evidence index (`evidence/`)

The screenshots keep their original timestamp names. The report uses five of them (cropped to the result rows); the other two are alternate views of the same results.

| File | Tool | Sample | What it shows |
|------|------|--------|---------------|
| `Screenshot 2026-10-13 110405.png` | Google Admin Toolbox | sample 10 (S2) | SPF none, DKIM none, DMARC permerror; sender is a lookalike domain |
| `Screenshot 2026-10-13 110454.png` | Google Admin Toolbox | sample 101 (S3) | From forged as `microsoft.com`: SPF none, DKIM fail, DMARC fail |
| `Screenshot 2026-10-13 110541.png` | Google Admin Toolbox | sample 7 (S7) | SPF, DKIM and DMARC all pass; relayed through Google's own server |
| `Screenshot 2026-10-13 112040.png` | MXToolbox | sample 2 (S4) | DMARC, SPF and DKIM checks all fail; relay through a Mailgun server |
| `Screenshot 2026-10-13 112031.png` | MXToolbox | sample 2 (S4) | Same result, scrolled further down to the relay table |
| `Screenshot 2026-10-13 112129.png` | MXToolbox | sample 115 (S6) | DMARC, SPF and DKIM checks fail (only SPF alignment passes); about 20 minutes delay on an unrelated company's server |
| `Screenshot 2026-10-13 112122.png` | MXToolbox | sample 115 (S6) | Same result, narrower view |

## Reproducing the analysis (optional)

Do this inside a disposable VM, never on a work machine. Perl is the only requirement. The commands read the email as text and pipe it straight into the scripts, so nothing is saved or opened:

```bash
curl -s https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-10.eml | perl tools/triage.pl
curl -s https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-10.eml | perl tools/headers.pl
curl -s https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-53.eml | perl tools/pdfpeek.pl
```

Do not open the raw `.eml` files in a mail client.

## Safety and privacy

- Raw `.eml` files are **not stored** in this repository, because they can contain live links and attachments.
- No link was clicked and no attachment was opened.
- Every web address that came from a phishing email is **defanged** (`hxxp://`, `[.]`) so nobody clicks one by accident.
- The phishing samples are public research data. The collector already anonymized the recipient (`phishing@pot`), and I redacted To/Cc-style headers as well.
- S8 is my own email, so it was redacted more heavily: name, address, profile details, tracking tokens and account-specific headers were removed.

## Limitations

- It is a small sample: eight emails, most of them from 2022 and 2023.
- Because I never opened a link or attachment, the "what happens next" parts of the report describe the usual pattern, not something I observed.
- The verdicts are my own judgement based on headers and content. Check results depend on what each receiving mail server recorded.

## Credits

- Real phishing emails: [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) by rf-peixoto, licensed [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/). Used here for non-commercial, educational analysis; the excerpts in this repository are modified (redacted and defanged).
- Header analysis tools: Google Admin Toolbox Messageheader and MXToolbox.
- Task brief and example email: Future Interns, Cyber Security Task 2.

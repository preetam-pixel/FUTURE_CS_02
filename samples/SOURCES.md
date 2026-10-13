# Sample sources and handling

## Where the emails came from

All real phishing emails in this project come from **Phishing Pot**
(https://github.com/rf-peixoto/phishing_pot), a public collection of real phishing emails gathered
by honeypots for researchers and detection developers. It is licensed
[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/); this project is non-commercial and
educational, credits the source, and only includes **modified excerpts** (defanged and redacted analysis
output), not the original `.eml` files. The collector already replaced their own address with
`phishing@pot`; I additionally redacted To/Cc-style headers.

Retrieved: 2026-10-13.

| ID | Original file | Attack type | Why I picked it |
|----|---------------|-------------|-----------------|
| S1 | Example from the Future Interns task brief | Generic "account will be locked" lure | The textbook example; body only, no headers available |
| S2 | [sample-10.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-10.eml) | Fake Microsoft sign-in alert, lookalike sender domain | Shows a lookalike domain and three different domains in From / Reply-To / Return-Path |
| S3 | [sample-101.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-101.eml) | Same lure, but spoofing the real `microsoft.com` | Pairs with S2: spoofed sender caught by SPF/DKIM/DMARC failures |
| S4 | [sample-2.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-2.eml) | Fake bank "verify your email" notice | Link hidden behind a search-engine redirect, generic greeting, pressure wording |
| S5 | [sample-53.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-53.eml) | Fake crypto "withdrawal error" with PDF attachment | Free webmail sender, link to a trusted cloud service hidden in the PDF |
| S6 | [sample-115.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-115.eml) | Advance-fee scam posing as the European Central Bank | Authority impersonation, fake domain, SPF softfail + DMARC fail |
| S7 | [sample-7.eml](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-7.eml) | Real Google notification abused to carry a lure | Passes every authentication check but is still suspicious |
| S8 | A genuine LinkedIn legal-notice email received by the student (Aug 2026) | Safe (control sample) | Shows what a normal, fully authenticated email looks like: SPF, DKIM and DMARC all pass, links only go to `linkedin.com` |

## How the samples were handled (safety)

- Emails were read as **plain text only**. Raw `.eml` files are **not stored** in this repository because they can contain live links and attachments.
- No link was visited and no attachment was opened. Attachments were inspected only by name, type and size, plus one static in-memory look at a PDF for embedded URLs (`tools/pdfpeek.pl`).
- Every web address that came **from a phishing email** is **defanged** (`hxxp://`, `[.]`) so nobody clicks one by accident. The ordinary links to GitHub and Creative Commons in this repository are left as normal links.
- **S8 (the safe control)** is the student's own email, so it was redacted more heavily: the recipient name, email address, profile headline, tracking tokens in links, the unique bounce-address token, signature blobs and a few account-specific headers were removed or replaced with `[redacted]`. Only the HTML-free text version of the body was analyzed.

## Files per sample

- `sample-N_triage.txt` : output of `tools/triage.pl`, a small read-only helper that lists key headers, authentication results, defanged links, attachments and automatic red-flag hints.
- `sample-N_headers.txt` : the raw header block (recipient redacted), ready to paste into the Google Admin Toolbox Messageheader tool or MXToolbox.
- `sample-53_pdf-peek.txt` : result of the static PDF look for sample 53.

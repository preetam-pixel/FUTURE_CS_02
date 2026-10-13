#!/usr/bin/perl
# headers.pl - prints ONLY the header block of one .eml (read from STDIN) with recipient addresses redacted.
# The output can be pasted into an email header analyzer (Google Admin Toolbox Messageheader, MXToolbox).
use strict; use warnings;
my $raw = do { local $/; <STDIN> };
$raw =~ s/\r\n?/\n/g;
my ($h) = split /\n\n/, $raw, 2;
$h //= '';
$h =~ s/phishing\@pot/recipient\@redacted.invalid/gi;
$h =~ s/(\bfor\s+)<[^>]+>/$1<recipient\@redacted.invalid>/gi;

my (@out, $skip);
for my $line (split /\n/, $h) {
    if ($line =~ /^(To|Cc|Bcc|Delivered-To|X-Original-To|X-Forwarded-To):/i) {
        push @out, "$1: [redacted]"; $skip = 1; next;
    }
    next if $skip && $line =~ /^[ \t]/;
    $skip = 0;
    push @out, $line;
}
print join("\n", @out), "\n";

#!/usr/bin/perl
# pdfpeek.pl - static, read-only peek at PDF attachments inside ONE .eml read from STDIN.
# Decodes the attachment in memory only (nothing is saved or opened) and lists URLs and risky PDF features.
use strict; use warnings;
use MIME::Base64 qw(decode_base64);
use Compress::Zlib ();

my $raw = do { local $/; <STDIN> };
$raw =~ s/\r\n?/\n/g;

sub defang { my $u = shift; $u =~ s/^http/hxxp/i; $u =~ s/\./[.]/g; return $u; }

my $found = 0;
for my $chunk (split /\n--[^\n]+\n/, $raw) {
    next unless $chunk =~ /Content-Type:\s*application\/pdf/i && $chunk =~ /base64/i;
    my (undef, $b64) = split /\n\n/, $chunk, 2;
    my $pdf = decode_base64($b64 // '');
    $found++;
    printf "PDF #%d: %d bytes, starts with '%s'\n", $found, length($pdf), substr($pdf, 0, 8) =~ s/[^\x20-\x7e]//gr;

    my $all = $pdf;
    while ($pdf =~ /stream\r?\n(.*?)\r?\nendstream/gs) {
        my $inflated = eval { Compress::Zlib::uncompress($1) };
        $all .= "\n" . $inflated if defined $inflated;
    }
    my %urls;
    $urls{$1}++ while $all =~ /\/URI\s*\(([^)]{1,300})\)/g;
    $urls{$1}++ while $all =~ m{(https?://[\w\-.~:/?#\[\]\@!\$&'*+,;=%]{4,200})}g;
    print "URL inside PDF: ", defang($_), "\n" for sort keys %urls;
    print "(no URLs found in plain or inflated PDF content)\n" unless %urls;
    for my $feat ('/JavaScript', '/JS', '/OpenAction', '/Launch', '/EmbeddedFile', '/AcroForm') {
        print "Contains $feat\n" if index($all, $feat) >= 0;
    }
}
print "(no PDF attachment found)\n" unless $found;

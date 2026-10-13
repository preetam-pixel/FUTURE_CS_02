#!/usr/bin/perl
# triage.pl - read-only phishing email triage.
# Reads ONE raw .eml on STDIN and prints headers, auth results, defanged links and red flags.
# It only parses text: it never opens attachments and never visits links.
use strict; use warnings; use utf8;
use MIME::Base64 qw(decode_base64);
use MIME::QuotedPrint qw(decode_qp);
use Encode qw(decode);
binmode(STDOUT, ':encoding(UTF-8)');

my $raw = do { local $/; <STDIN> };
$raw =~ s/\r\n?/\n/g;

sub split_msg { my ($t) = @_; my ($h, $b) = split(/\n\n/, $t, 2); return ($h // '', $b // ''); }
sub parse_headers {
    my ($h) = @_; my @out;
    for my $line (split /\n/, $h) {
        if ($line =~ /^[ \t]+(.*)$/ && @out) { $out[-1][1] .= ' ' . $1; }
        elsif ($line =~ /^([^:\s]+):[ \t]*(.*)$/) { push @out, [$1, $2]; }
    }
    return @out;
}
sub hdr { my ($hs, $n) = @_; return map { $_->[1] } grep { lc($_->[0]) eq lc($n) } @$hs; }
sub dec { my ($v) = @_; $v //= ''; my $d = eval { decode('MIME-Header', $v) }; return defined $d ? $d : $v; }
sub defang { my ($u) = @_; $u =~ s/^http/hxxp/i; $u =~ s/\./[.]/g; return $u; }
sub redact { my ($v) = @_; $v =~ s/phishing\@pot/[recipient]/gi; $v =~ s/[\w.+\-]+\@[\w.\-]+\.[A-Za-z]{2,}/[redacted-address]/g; return $v; }
sub regdom {
    my @l = split /\./, lc(shift // ''); return join('.', @l) if @l <= 2;
    return (length($l[-2]) <= 3 && length($l[-1]) == 2) ? join('.', @l[-3 .. -1]) : join('.', @l[-2, -1]);
}
sub html_entities {
    my $t = shift // '';
    my %e = (amp => '&', lt => '<', gt => '>', quot => '"', apos => "'", nbsp => ' ');
    $t =~ s/&#x([0-9a-f]+);/chr(hex($1))/gie;
    $t =~ s/&#(\d+);/chr($1)/ge;
    $t =~ s/&(\w+);/exists $e{lc $1} ? $e{lc $1} : "&$1;"/ge;
    return $t;
}
sub html2text {
    my $h = shift // '';
    $h =~ s/<(script|style)\b.*?<\/\1>//gis; $h =~ s/<!--.*?-->//gs;
    $h =~ s/<br\s*\/?>/\n/gi; $h =~ s/<\/(p|div|tr|li|h\d|table)>/\n/gi; $h =~ s/<[^>]+>//g;
    $h = html_entities($h); $h =~ s/[ \t]+/ /g; $h =~ s/\n\s*\n+/\n\n/g;
    return $h;
}

my ($htxt) = split_msg($raw);
my @H = parse_headers($htxt);

my @parts;
sub walk {
    my ($text) = @_;
    my ($h, $b) = split_msg($text);
    my @hs = parse_headers($h);
    my ($ct) = hdr(\@hs, 'Content-Type'); $ct //= 'text/plain';
    my ($cte) = hdr(\@hs, 'Content-Transfer-Encoding'); $cte = lc($cte // '7bit'); $cte =~ s/\s.*//;
    my ($cd) = hdr(\@hs, 'Content-Disposition'); $cd //= '';
    if ($ct =~ m{^\s*multipart/}i && $ct =~ /boundary\s*=\s*"?([^";\s]+)"?/i) {
        my $bd = quotemeta($1);
        my @chunks = split(/(?:^|\n)--$bd(?:--)?[ \t]*(?:\n|$)/, $b);
        shift @chunks;
        walk($_) for grep { /\S/ } @chunks;
        return;
    }
    my ($type) = lc($ct) =~ m{^\s*([\w\-./+]+)};
    my ($cs) = $ct =~ /charset\s*=\s*"?([\w\-]+)"?/i;
    my ($fn) = ($cd =~ /filename\*?\s*=\s*"?([^";]+)"?/i);
    ($fn) = ($ct =~ /name\s*=\s*"?([^";]+)"?/i) unless defined $fn;
    push @parts, { type => ($type // 'text/plain'), cs => $cs, enc => $cte, fn => $fn, att => ($cd =~ /attachment/i ? 1 : 0), raw => $b };
}
walk($raw);

sub part_text {
    my ($p) = @_; my $d = $p->{raw};
    if ($p->{enc} eq 'base64') { $d = decode_base64($d); }
    elsif ($p->{enc} eq 'quoted-printable') { $d = decode_qp($d); }
    my $cs = $p->{cs} // 'utf-8';
    my $t = eval { decode($cs, $d, Encode::FB_DEFAULT) };
    $t = decode('UTF-8', $d, Encode::FB_DEFAULT) unless defined $t;
    return $t;
}

my ($plain, $html, @atts) = ('', '');
for my $p (@parts) {
    if ($p->{type} eq 'text/plain' && !$p->{att}) { $plain .= part_text($p) . "\n"; }
    elsif ($p->{type} eq 'text/html' && !$p->{att}) { $html .= part_text($p) . "\n"; }
    else {
        my $sz = $p->{enc} eq 'base64' ? int(length($p->{raw}) * 3 / 4) : length($p->{raw});
        push @atts, { type => $p->{type}, fn => ($p->{fn} // '(no name)'), size => $sz };
    }
}

print "=== KEY HEADERS ===\n";
for my $n (qw(From Reply-To Return-Path Sender To Cc Subject Date Message-ID X-Mailer User-Agent X-Originating-IP List-Unsubscribe Precedence)) {
    for my $v (hdr(\@H, $n)) {
        my $o = dec($v);
        $o = redact($o) if $n =~ /^(To|Cc)$/i;
        print "$n: ", substr($o, 0, 220), "\n";
    }
}

print "\n=== RECEIVED CHAIN (top = last hop before the recipient) ===\n";
my @rec = hdr(\@H, 'Received'); my $ri = 0;
print "[", ++$ri, "] ", substr(redact($_), 0, 230), "\n" for @rec;
print "(none recorded)\n" unless @rec;

print "\n=== AUTHENTICATION ===\n";
my @auth = (hdr(\@H, 'Authentication-Results'), hdr(\@H, 'Received-SPF'), hdr(\@H, 'ARC-Authentication-Results'));
print substr(redact($_), 0, 320), "\n" for @auth;
my @dkim = hdr(\@H, 'DKIM-Signature');
for my $d (@dkim) { my ($dd) = $d =~ /\bd=([^;\s]+)/; my ($ss) = $d =~ /\bs=([^;\s]+)/; print "DKIM-Signature: d=", ($dd // '?'), " s=", ($ss // '?'), "\n"; }
print "(no SPF/DKIM/DMARC headers recorded in this sample)\n" unless @auth || @dkim;

my $shown = $plain =~ /\S/ ? $plain : html2text($html);
$shown =~ s/[ \t]+/ /g; $shown =~ s/\n{3,}/\n\n/g; $shown = redact($shown);
print "\n=== BODY (first 1400 chars, decoded) ===\n", substr($shown, 0, 1400), "\n";

my @links;
while ($html =~ /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)<\/a>/gis) {
    my $u = $1 // $2 // $3 // ''; my $t = $4 // '';
    $t =~ s/<[^>]+>//g; $t = html_entities($t); $t =~ s/\s+/ /g; $t =~ s/^ | $//g;
    push @links, [html_entities($u), $t];
}
for my $src ($plain, html2text($html)) {
    while ($src =~ m{(https?://[^\s<>"')\]]+)}gi) { my $u = $1; push @links, [$u, '(bare URL in text)'] unless grep { $_->[0] eq $u } @links; }
}
my (%seen, @uniq);
for my $l (@links) { next if $seen{$l->[0]}++; push @uniq, $l; }
print "\n=== LINKS (defanged, never click) ===\n";
my $ln = 0;
for my $l (@uniq) { last if ++$ln > 15; printf "- %s  (shown as: \"%s\")\n", defang(substr($l->[0], 0, 130)), substr($l->[1], 0, 60); }
print "(no links found)\n" unless @uniq;
printf "Total unique links: %d\n", scalar @uniq;

print "\n=== ATTACHMENTS (names/types only, never opened) ===\n";
print "- $_->{fn} [$_->{type}] ~$_->{size} bytes\n" for @atts;
print "(none)\n" unless @atts;

# ---- automatic red-flag hints ----
my ($from) = hdr(\@H, 'From'); $from = dec($from // '');
my ($subj) = hdr(\@H, 'Subject'); $subj = dec($subj // '');
my ($faddr) = $from =~ /<([^>]+)>/; $faddr //= (($from =~ /([\w.+\-]+\@[\w.\-]+)/)[0] // '');
my ($fdom) = $faddr =~ /\@([\w.\-]+)/; $fdom = lc($fdom // '');
my ($fname) = $from =~ /^\s*"?([^"<]*?)"?\s*</; $fname //= '';
my ($rp) = hdr(\@H, 'Return-Path'); my ($rpdom) = ($rp // '') =~ /\@([\w.\-]+)>?\s*$/;
my ($rt) = hdr(\@H, 'Reply-To'); my ($rtdom) = ($rt // '') =~ /\@([\w.\-]+)>?\s*$/;
my @flags;
push @flags, "From domain is '$fdom'" if $fdom;
push @flags, "Return-Path domain ($rpdom) differs from From domain ($fdom)" if $rpdom && $fdom && regdom($rpdom) ne regdom($fdom);
push @flags, "Reply-To domain ($rtdom) differs from From domain ($fdom)" if $rtdom && $fdom && regdom($rtdom) ne regdom($fdom);
push @flags, "Sender uses a free webmail address ($fdom)" if $fdom =~ /^(gmail|yahoo|hotmail|outlook|live|aol|protonmail|gmx|mail|icloud)\./;
push @flags, "Empty or missing sender address in From" if $from && !$faddr;
if ($fname =~ /(microsoft|paypal|apple|google|amazon|facebook|netflix|bank|binance|coinbase|metamask|ledger|exodus|trust|dhl|fedex|ups|usps|postnl|ecb|fbi)/i) {
    my $brand = lc($1); push @flags, "Display name mentions '$brand' but the sending domain is '$fdom'" unless $fdom =~ /\Q$brand\E/;
}
push @flags, "Non-ASCII characters in From/Subject (possible lookalike or obfuscation)" if ($from . $subj) =~ /[^\x00-\x7F]/;
push @flags, "Mixed Latin + Cyrillic/Greek letters (homoglyph trick)" if ($from . $subj) =~ /[\p{Cyrillic}\p{Greek}]/ && ($from . $subj) =~ /[A-Za-z]/;
my $alltext = lc($subj . ' ' . $shown);
my %urg; $urg{$1}++ while $alltext =~ /\b(urgent|immediately|within 24|suspend\w*|locked?|verify|confirm\w*|expire\w*|final notice|action required|act now|unusual|unauthori[sz]ed|security alert|blocked|disabled|limited time)\b/g;
push @flags, "Urgency/fear wording: " . join(', ', sort keys %urg) if %urg;
my %prz; $prz{$1}++ while $alltext =~ /\b(winner|won|winning|congratulations|lottery|beneficiary|inheritance|funds?|million|prize|reward|free)\b/g;
push @flags, "Prize/money wording: " . join(', ', sort keys %prz) if %prz;
push @flags, "Generic greeting (no real name)" if substr($shown, 0, 300) =~ /\b(dear|hello|hi)\s+(user|customer|client|member|friend|sir|madam|valued|account holder|beneficiary)/i;
for my $l (@uniq) {
    my ($u, $t) = @$l; my ($h) = $u =~ m{^[a-z]+://([^/:?#]+)}i; next unless $h;
    if ($t =~ m{(?:https?://)?([\w\-]+(?:\.[\w\-]+)+)} && regdom($1) ne regdom($h)) { push @flags, "Link text shows '$1' but the link goes to '$h'"; last; }
}
my %lh; for my $l (@uniq) { my ($h) = $l->[0] =~ m{^[a-z]+://([^/:?#]+)}i; $lh{lc $h}++ if $h; }
push @flags, "Link domains: " . join(', ', map { defang("http://$_") =~ s/^hxxp:\/\///r } sort keys %lh) if %lh;
for my $a (@atts) { push @flags, "Attachment type often abused: $a->{fn}" if ($a->{fn} // '') =~ /\.(exe|scr|js|vbs|zip|rar|iso|html?|docm|xlsm|lnk|pdf|img|7z)$/i; }
print "\n=== AUTO FLAGS (hints for the analyst, not a verdict) ===\n";
print "- $_\n" for @flags;

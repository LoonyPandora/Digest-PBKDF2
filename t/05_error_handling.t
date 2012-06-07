use Test::More tests => 6;

use strict;
use warnings;

use Digest::PBKDF2;
use Test::Exception;


my $ctx = Digest::PBKDF2->new;

$ctx->add('passphrase');

throws_ok(sub { $ctx->digest }, qr/No salt specified/, 'Dies when salt not specified');

lives_ok(sub { $ctx->salt('foo') }, 'Can set salt');
lives_ok(sub { $ctx->salt('bar') }, 'Can re-set the salt to another value');

is($ctx->salt, 'bar', 'Salt method replaces data');


my $ctx2 = Digest::PBKDF2->new;
$ctx2->add('passphrase');
$ctx2->salt('salt');

throws_ok(sub { $ctx2->digest }, qr/Invalid iteration count/, 'Dies when iteration count not specified');

throws_ok(
    sub {
        $ctx2->iterations(999);
        $ctx2->digest;
    },
    qr/Invalid iteration count/,
    'Dies when iteration count out of range'
);

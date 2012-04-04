use Test::More tests => 4;

use strict;
use warnings;

use Digest::PBKDF2;
use Test::Exception;


my $ctx = Digest::PBKDF2->new;

$ctx->add('cool');

throws_ok(sub { $ctx->digest }, qr/Salt must be specified/, 'Dies when salt not specified');

lives_ok(sub { $ctx->salt('foo') }, 'Can set salt');
lives_ok(sub { $ctx->salt('bar') }, 'Can re-set the salt to another value');

is($ctx->salt, 'bar', 'Salt method replaces data');

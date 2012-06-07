use Test::More tests => 2;

use strict;
use warnings;

use Digest;
use Digest::PBKDF2;


my $direct = Digest::PBKDF2->new;
can_ok($direct, qw/new clone add digest hexdigest b64digest salt iterations as_crypt as_ldap reset/);

my $indirect = Digest->new('PBKDF2');
can_ok($indirect, qw/new clone add digest hexdigest b64digest salt iterations as_crypt as_ldap reset/);

use Test::More tests => 6;

use strict;
use warnings;

use Digest::PBKDF2;

# $ctx is reset after each digest, hence why we re-add the salt / data
my $ctx = Digest::PBKDF2->new;

$ctx->add('cool');
$ctx->salt('salt');

ok($ctx->digest, "Creates Binary Digest");


$ctx->add('cool');
$ctx->salt('');

ok($ctx->hexdigest eq '7d564b4dd7566702bbea294abc256b7ecff7dc69', "Creates Correct Digest With Empty Salt");


$ctx->add('cool');
$ctx->salt('salt');

ok($ctx->hexdigest eq '889a3bf0c83f691ed3dd09be4dca141a561fbb90', "Creates Correct Hex Digest");


$ctx->add('cool');
$ctx->salt('salt');

ok($ctx->b64digest eq 'iJo78Mg/aR7T3Qm+TcoUGlYfu5A', "Creates Correct Base 64 Digest");


$ctx->add('cool');
$ctx->salt('salt');

ok($ctx->as_crypt eq '$PBKDF2$HMACSHA1:1000:c2FsdA==$iJo78Mg/aR7T3Qm+TcoUGlYfu5A=', "Creates Correct Crypt Digest");


$ctx->add('cool');
$ctx->salt('salt');

ok($ctx->as_ldap eq '{X-PBKDF2}HMACSHA1:AAAD6A:c2FsdA==:iJo78Mg/aR7T3Qm+TcoUGlYfu5A=', "Creates Correct LDAP / RFC 2307 Digest");



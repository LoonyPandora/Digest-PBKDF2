use Test::More tests => 12;

use strict;
use warnings;

use Digest::PBKDF2;
use Scalar::Util qw(refaddr);
use Test::Exception;


my $orig = Digest::PBKDF2->new;

lives_ok( sub { $orig->add('cool')  }, "I can add one chunk" );
lives_ok( sub { $orig->add('jazz')  }, "I can add another chunk" );
lives_ok( sub { $orig->salt('salt') }, "I can add salt" );

my $clone;

lives_ok( sub { $clone = $orig->clone }, "I can clone my object" );

isnt(
    refaddr $orig,
    refaddr $clone,
    "Cloning gives me a new Digest::PBKDF2 object"
);

isnt(
    refaddr \$orig->{_data},
    refaddr \$clone->{_data},
    "Cloning gives me a new data slot"
);

lives_ok(sub { delete $clone->{_data} }, "I can delete the data in my clone");

is($clone->{_data}, undef,      "And the data is gone");

is($orig->{_data},  'cooljazz', "And the original remains intact");

lives_ok(sub { $clone->add('cooljazz') }, "I can put back the clone data");


my ($clone_digest, $orig_digest) = ($clone->hexdigest, $orig->hexdigest);

is($clone_digest, $orig_digest, "Clone and orginal produce the same string");

is(
    $orig_digest,
    'ec97d051d529a3d016e17d7a71a69c1124e37f89',
    "And that string is what it should be"
);


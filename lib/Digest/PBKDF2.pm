package Digest::PBKDF2;

# ABSTRACT: This module is a subclass of Digest using the Crypt::PBKDF2 algorithm.

use strict;

use parent "Digest::base";
use Carp qw(croak);
use Crypt::PBKDF2 0.112020;

# VERSION

sub new {
    my $class = shift;

    return bless {
        _data => '',
    }, ref($class) || $class;
}


sub as_crypt {
    my $self = shift;

    return $self->_with_encoding('crypt');
}


sub as_ldap {
    my $self = shift;

    return $self->_with_encoding('ldap');
}

sub salt {
    my ($self, $salt) = @_;

    # Salt set to the empty string is valid, though strongly discouraged.
    # It is only accepted for backwards compatibility.
    if (defined $salt) {
        $self->{salt} = $salt;
        return $self;
    }

    return $self->{salt};
}


sub clone {
    my $self = shift;

    return bless {
        salt  => $self->salt,
        _data => $self->{_data},
    }, ref($self);
}


sub reset {
    my $self = shift;

    delete $self->{salt};
    delete $self->{_data};

    return $self->new;
}


sub add {
    my $self = shift;

    $self->{_data} .= join('', @_);

    return $self;
}


sub digest {
    my $self = shift;

    if (!defined $self->salt) {
        croak "Salt must be specified. If you want no salt, you must explicitly set it to the empty string";
    }

    my $hash = Crypt::PBKDF2->new()->PBKDF2($self->salt, $self->{_data});

    $self->reset;

    return $hash;
}


sub _with_encoding {
    my ($self, $encoding) = @_;

    my $crypt = Crypt::PBKDF2->new(
        encoding => $encoding,
    );

    my $hash = $crypt->generate($self->{_data}, $self->salt);

    $self->reset;

    return $hash;
}


1;

__END__

=head1 NAME

Digest::PBKDF2

A minimalist Digest module using the PBKDF2 algorithm.

=head1 SYNOPSIS

    # via the Digest module (recommended)
    use Digest;

    my $pbkdf2 = Digest->new('PBKDF2');

    # $salt is essential, and should be cryptographically random
    $pbkdf2->salt($salt);

    $pbkdf2->add('password');      # password = 'password'
    $pbkdf2->add('extension');     # password = 'passwordextension'

    $digest = $pbkdf2->digest;     # Binary version, 20 bytes
    $digest = $pbkdf2->hexdigest;  # Hex-encoded, 42 bytes
    $digest = $pbkdf2->b64digest;  # base64 encoded with no padding. 27 bytes

    # [...]

    # Using the module directly (same interface as above)

    use Digest::PBKDF2;

    my $pbkdf2 = Digest::PBKDF2->new();

=head1 METHODS

=over

=item new

    my $pbkdf2 = Digest->new('PBKDF2');

Creates a new C<Digest::PBKDF2> object.

You can also use this module directly

    my $pbkdf2 = Digest::PBKDF2->new();

=item clone

    my $pbkdf2->clone;

Copies the data and state from the original C<Digest::PBKDF2> object,
and returns a new object.

=item add

    $pbkdf2->add("a"); $pbkdf2->add("b"); $pbkdf2->add("c");
    $pbkdf2->add("a")->add("b")->add("c");
    $pbkdf2->add("a", "b", "c");
    $pbkdf2->add("abc");

Adds data to the message we are calculating the digest for.

All the above examples have the same effect

=item salt

    $pbkdf2->salt($salt);

Sets the value to be used as a salt. You must specify a salt.

It is recommenced that you use a module like L<Data::Entropy::Algorithms> to
provide a truly randomised salt.

When called with no arguments, will return the whatever is the current salt

=item digest

    $pbkdf2->digest;

Return the binary digest for the message.

The returned string will be 20 bytes long.

=item hexdigest

    $pbkdf2->hexdigest;

Same as L</"digest">, but will return the digest in hexadecimal form.

The C<length> of the returned string will be 42 and will only contain
characters from the ranges C<'0'..'9'> and C<'a'..'f'>.

=item b64digest

    $pbkdf2->b64digest;

Same as L</"digest">, but will return the digest base64 encoded.

The C<length> of the returned string will be 27 and will only contain characters 
from the ranges C<'0'..'9'>, C<'A'..'Z'>, C<'a'..'z'>, C<'+'>, and C<'.'>

The base64 encoded string returned is not padded to be a multiple of 4 bytes long.

=item reset

    $pbkdf2->reset;

Resets the object to the same internal state it was in when it was constructed.

=item as_crypt

    $pbkdf2->as_crypt;
    
Returns the digest, salt, and algorithm as a string that is similar to that used
by the C<crypt()> function. Example:

    $PBKDF2$HMACSHA1:1000:4q9OTg==$9Pb6bCRgnct/dga+4v4Lyv8x31s=

The output of this method is the same as the outpout from the 
C<generate> function of L<Crypt::PBKDF2> when using the C<crypt> encoding method


=item as_ldap

    $pbkdf2->as_ldap;

Returns the digest, salt, and algorithm as a string that is intended to be
compatible with RFC 2307. Example:

    {X-PBKDF2}HMACSHA1:AAAD6A:8ODUPA==:1HSdSVVwlWSZhbPGO7GIZ4iUbrk=

The output of this method is the same as the outpout from the 
C<generate> function of L<Crypt::PBKDF2> when using the C<crypt> encoding method

=back

=head1 SEE ALSO

L<Crypt::PBKDF2>
L<Digest>

=head1 AUTHOR

Amiri Barksdale, E<lt>abarksdale@campusexplorer.comE<gt>

James Aitken, E<lt>jaitken@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 by Campus Explorer, Inc.

L<http://www.campusexplorer.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

package Digest::PBKDF2;

use strict;

use parent "Digest::base";
use Crypt::PBKDF2 0.112020;

our $VERSION = '0.1.0';

# ABSTRACT: This module is a subclass of Digest using the Crypt::PBKDF2 algorithm.

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

    if ($salt) {        
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

    my $pbkdf2 = Crypt::PBKDF2->new;

    my $hash = $pbkdf2->PBKDF2($self->salt, $self->{_data});

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

=head1 NOTICE

You can only use one salt, a pre-salt, with this module. It is not smart enough
to do post-salts.

=head1 SYNOPSIS

    my $digest = Digest::PBKDF2->new;   # Or...
    my $digest = Digest::PBKDF2->new(encoding => 'ldap');
    $digest->add('mysalt');             # salt = 'mysalt'
    $digest->add('k3wLP@$$w0rd');       # password = 'k3wLP@$$w0rd'

    $digest->add('eX+ens10n');          # password = 'k3wLP@$$w0rdeX+ens10n'

    my $result = $digest->digest;       # $PBKDF2$HMACSHA1:1000:bXlzYWx0$4P9pwp
                                        # LoF+eq5jwUbMw05qRQyZs=

That's about it.

=head1 METHODS

=over

=item new

Create a new Digest::PBKDF2 object. This defaults to using the "crypt" encoding
available in Crypt::PBKDF2--please see L<Crypt::PBKDF2> for details.

=item clone

Copies the data and state from the original Digest::PBKDF2 object,
and returns a new object.

=item add

Pass this method your salt and data chunks. They are stored up
until you call digest.

=item digest

This encrypts your data and returns the encrypted string.

=item reset

After calling digest, the module calls reset on its self,
clearing data and the record of how many additions were made to the data
to be digested.

=back

=head1 SEE ALSO

L<Crypt::PBKDF2>
L<Digest>

=head1 AUTHOR

Amiri Barksdale, E<lt>abarksdale@campusexplorer.comE<gt>

=head1 COPYRIGHT

Copyright (c) 2011 by Campus Explorer, Inc.

L<http://www.campusexplorer.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

use strict;
use warnings;
package WebService::Coinbase;
use Moo;
with 'WebService::BaseClientRole';

# ABSTRACT: Simple client for Coinbase API

use Crypt::Mac::HMAC qw(hmac_hex);
use Time::HiRes qw(time);

has api_key     => ( is => 'ro', required => 1 );
has api_secret  => ( is => 'ro', required => 1 );
has '+base_url' => ( default => 'https://coinbase.com/api/v1' );

# Calculate the NONCE + ACCESS_SIGNATURE headers for AUTH
around _req => sub {
    my ($orig, $self, $req) = (shift, shift, shift);
    my $nonce = time * 1E5;
    my $sig   = hmac_hex('SHA256', $self->api_secret,
        $nonce, $req->uri, $req->content);
    $req->header(
        ACCESS_KEY => $self->api_key,
        ACCESS_NONCE => $nonce,
        ACCESS_SIGNATURE => $sig,
    );
    return $self->$orig($req, @_);
};

sub create_button {
    my ($self, $data) = @_;
    return $self->post("/buttons", { button => $data });
}

1;

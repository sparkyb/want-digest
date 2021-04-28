# nginx Embedded Perl module for adding a Digest header using the algorithm
# specified in the Want-Digest header.
#
# Author: Esmé Cowles <escowles@ticklefish.org>
# License: http://www.nginx.org/LICENSE
#
# Derived from example code by Matt Martz <matt@sivel.net>
# Link: https://gist.github.com/1870822#file_content_md5.pm

package WantDigest;
use nginx;
use Digest::MD5;
use Digest::SHA;
use MIME::Base64;

sub handler {
    my $r = shift;
    my $filename = $r->filename;
    return DECLINED unless -f $filename;

    my $want_digest = $r->header_in("Want-Digest");
    return DECLINED unless $want_digest;
    my @digests = map {
      /^\s*([^\s;]+)(?:;q=([01](?:\.\d)?))?\s*$/ ? { algo => $1, q => $2 eq "" ? 1 : $2 } : ();
    } split(/,\s*/, $want_digest);
    @digests = sort { -($a->{q} <=> $b->{q}) } @digests;
    @digests = map { $_->{q} > 0 ? $_->{algo} : () } @digests;
    my $algo;
    my $ctx;
    for (@digests) {
        $algo = $_;
        if ( lc($algo) eq "md5" ) {
            $ctx = Digest::MD5->new;
        } elsif ( lc($algo) eq "sha" ) {
            $ctx = Digest::SHA->new(1);
        } elsif ( lc($algo) eq "sha-256" ) {
            $ctx = Digest::SHA->new(256);
        } elsif ( lc($algo) eq "sha-512" ) {
            $ctx = Digest::SHA->new(512);
        }
        last if ( $ctx );
    }

    if ( $ctx ) {
      open( FILE, $filename ) or return DECLINED;
      $ctx->addfile( *FILE );
      my $digest = encode_base64 $ctx->digest;
      close( FILE );
      $r->header_out( "Digest", "$algo=$digest" );
    } else {
      $r->header_out( "Want-Digest", "md5, sha, sha-256, sha-512" );
      return HTTP_BAD_REQUEST;
    }

    return DECLINED;
}

1;
__END__

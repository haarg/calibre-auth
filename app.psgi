use strict;
use warnings;
use Plack::Builder;
use Calibre::Auth;

builder {
  enable 'ReverseProxy';
  mount '/auth' => Calibre::Auth->new->to_app;
  mount '/' => sub { [ 404, [ 'Content-Type' => 'text/plain' ], [ 'Not Found' ] ] };
};

use strict;
use warnings;
use Plack::Builder;
use Calibre::Auth;

builder {
  enable 'ReverseProxy';
  Calibre::Auth->new->to_app;
};

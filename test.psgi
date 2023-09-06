use strict;
use warnings;
use experimental qw(signatures);

use Plack::Builder;
use Plack::App::Proxy;
use Calibre::Auth;
use Plack::Util ();

my $auth = Calibre::Auth->new->to_app;
my $auth_mount = 'auth';

builder {
  mount "/$auth_mount" => $auth,
  mount '/'     => builder {
    enable sub ($app) {
      sub ($env) {
        open my $in, '<', \'';
        my $auth_env = {
          %$env,
          SCRIPT_NAME => ($env->{SCRIPT_NAME} || '') . "/$auth_mount",
          PATH_INFO => '/auth' . $env->{PATH_INFO},
          'psgi.input' => $in,
        };

        my $auth_output = $auth->($auth_env);
        if ($auth_output->[0] >= 400) {
          return [ 302, [ 'Location' => "/$auth_mount" ], [''] ];
        }
        my $auth = Plack::Util::header_get($auth_output->[1], 'X-Calibre-Auth-Header');
        if ($auth) {
          $env->{HTTP_AUTHORIZATION} = $auth;
        }
        return $app->($env);
      };
    };
    enable sub ($app) {
      sub ($env) {
        delete $env->{HTTP_ACCEPT_ENCODING};
        Plack::Util::response_cb($app->($env), sub ($res) {
          push @{ $res->[1] }, 'Link', "</$auth_mount/static/calibre-extras.css>;rel=stylesheet";
        });
      };
    };
    enable 'SimpleContentFilter', (
      filter => sub {
        s{ To log in as a different user, you will have to restart the browser\.}{};
        s{, you will be asked for the new password the next time the browser has to contact the calibre server}{};
#        s{(</head>)}{
#          <link rel="stylesheet" href="/auth/static/calibre-extras.css" type="text/css">
#          <script src="/auth/static/calibre-extras.js" type="text/javascript" defer></script>
#          $1
#        };
        s{(create_button\(_\("Change password"\),)}{
          create_button(_("Logout"), null, function() {
            var logout_xhr = new XMLHttpRequest();
            logout_xhr.onload = (e) => {
              document.location = '/';
            };
            logout_xhr.open("POST", "/$auth_mount/logout");
            logout_xhr.send(null);
            close_modal();
          }), " ", $1
        };
      },
    );
    Plack::App::Proxy->new(
      remote => 'http://127.0.0.1:8080/',
      backend => 'LWP',
    )->to_app;
  };
};

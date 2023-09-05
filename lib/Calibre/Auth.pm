package Calibre::Auth;
use strict;
use warnings;

use Plack::Builder;
use Config::ZOMG;
use Plack::App::File;
use File::Basename qw(dirname);
use File::Spec::Functions qw(abs2rel);
use Cwd qw(abs_path);
use MIME::Base64 qw(encode_base64 decode_base64);
use Text::Xslate;
use Plack::Request;
use Crypt::Passphrase;
use DBIx::Connector;
use JSON::MaybeXS qw(encode_json decode_json);

use Moo;
use namespace::clean;
use experimental qw(signatures);

has base_path => (
  is => 'ro',
  default => sub {
    abs_path(dirname(__FILE__) . '/../../');
  },
);

has config => (
  is => 'lazy',
  default => sub ($self) {
    Config::ZOMG->new(
      name => __PACKAGE__,
      path => $self->base_path,
    )->load;
  },
);

has calibre_root => (
  is => 'lazy',
  default => sub ($self) {
    $self->config->{calibre_root};
  },
);

has root => (
  is => 'lazy',
  default => sub ($self) {
    $self->base_path . '/root';
  },
);

has static => (
  is => 'lazy',
  default => sub ($self) {
    $self->root . '/static';
  },
);

has static_app => (
  is => 'lazy',
  default => sub ($self) {
    Plack::App::File->new(root => $self->static)->to_app;
  },
);

has user_db => (
  is => 'ro',
  default => sub ($self) {
    $self->config->{user_db};
  },
);

has _connector => (
  is => 'lazy',
  init_arg => undef,
  default => sub ($self) {
    my $connector = DBIx::Connector->new(
      'dbi:SQLite:dbname=' . $self->user_db, '', '', {
        RaiseError => 1,
      },
    );

    return $connector;
  },
);

sub dbh ($self) {
  $self->_connector->dbh;
}

has session_secret => (
  is => 'lazy',
  default => sub ($self) {
    $self->config->{session_secret},
  },
);

has crypt => (
  is => 'lazy',
  default => sub ($self) {
    Crypt::Passphrase->new(%{ $self->config->{crypt} });
  },
);

has template_cache => (
  is => 'lazy',
  default => sub ($self) {
    File::Temp->newdir(
      TEMPLATE  => 'calibre-auth-cache-XXXXXX',
      TMPDIR    => 1,
      CLEANUP   => 1,
    );
  },
);

has renderer => (
  is => 'lazy',
  default => sub ($self) {
    my $tx = Text::Xslate->new(
      cache => 2,
      cache_dir => $self->template_cache,
      path => [ $self->root ],
      syntax => 'Metakolon',
      module => ['Text::Xslate::Bridge::Star'],
    );
  },
);

has table_name => (
  is => 'ro',
  default => 'user_login',
);

sub BUILD ($self, $args) {
  $self->crypt;
  my $renderer = $self->renderer;
  File::Find::find({
    no_chdir => 1,
    wanted => sub {
      return
        unless -f && /\.tx$/;
      $renderer->load_file(abs2rel($_, $self->root));
    },
  }, $self->root);


  my $dbh = $self->dbh;

  my $sth = $dbh->table_info(undef, 'main', 'user_login', 'TABLE');
  my $res = $sth->fetchall_arrayref;
  if (@$res == 0) {
    my $table = $self->table_name;
    $dbh->do("CREATE TABLE $table ( name TEXT PRIMARY KEY, passphrase TEXT NOT NULL )");
  }
}

sub to_app ($self) {
  builder {
    enable 'Session::Cookie',
      session_key => 'calibre-auth',
      expires     => 365*24*60*60,
      secret      => $self->session_secret,
      serializer    => sub ($data) { encode_base64( encode_json($data) ) },
      deserializer  => sub ($data) { decode_json( decode_base64($data) ) },
    ;
    mount '/static/'    => $self->static_app;
    mount '/'           => sub ($env) { $self->call($env) };
  };
}

sub call ($self, $env) {
  my $req = Plack::Request->new($env);
  $req->request_body_parser->register('application/json', 'HTTP::Entity::Parser::JSON');

  my $path = $req->path_info;
  $path = '/'
    if $path eq '';

  if ($path =~ m{^/change-pw$}) {
    return $self->change_pw($req);
  }
  elsif ($path =~ m{^/auth(?:/|$)}) {
    return $self->auth($req);
  }
  elsif ($path =~ m{^/logout$}) {
    return $self->logout($req);
  }
  elsif ($path =~ m{^/$}) {
    return $self->login($req);
  }
  else {
    return [ 404, [ 'Content-Type' => 'text/plain; charset=UTF-8' ], [ 'Not Found' ] ];
  }
}

sub change_pw ($self, $req) {
  $req->env->{'psgix.session'}->{logged_in}
    or return [ 400, [], [] ];
  my $user = $req->env->{'psgix.session'}->{user}
    or return [ 400, [], [] ];
  my $old_pw = $req->body_parameters->get('oldpw');
  my $new_pw = $req->body_parameters->get('newpw');

  if (!$self->check_password($user, $old_pw)) {
    return [ 401, [ 'Content-Type' => 'text/plain; charset=UTF-8' ], [ 'Existing password is incorrect' ] ];
  }

  $self->set_password($user, $new_pw);
  return [ 200, [ 'Content-Type' => 'text/plain; charset=UTF-8' ], [ "password for $user changed" ] ];
}

sub set_password ($self, $user, $password) {
  my $pass_hash = $self->crypt->hash_password($password);
  my $table = $self->table_name;

  $self->dbh->do(
    "INSERT OR REPLACE INTO $table (name, passphrase) VALUES (?, ?)",
    {},
    $user, $pass_hash,
  );

  return 1;
}

sub check_password ($self, $user, $password, $rehash = 0) {
  my $table = $self->table_name;
  my $data = $self->dbh->selectall_arrayref("SELECT passphrase FROM $table WHERE name = ?", {}, $user);
  if (@$data != 1) {
    return undef;
  }
  my $pass_hash = $data->[0][0]
    or return undef;

  $self->crypt->verify_password($password, $pass_hash)
    or return 0;

  if ($rehash && $self->crypt->needs_rehash($pass_hash)) {
    $self->set_password($password);
  }

  return 1;
}

sub auth ($self, $req) {
  $req->env->{'psgix.session'}->{logged_in}
    or return [401, [], []];
  my $user = $req->env->{'psgix.session'}->{user}
    or return [401, [], []];

  my $data = $self->dbh->selectall_arrayref('SELECT pw FROM users WHERE name = ?', {}, $user);
  return [401, [], []]
    if !@$data == 1;
  my $password = $data->[0][0];

  my $auth_header = 'Basic ' . encode_base64($user . ':' . $password, '');
  return [200, [
    'Vary' => 'Cookie',
    'Cache-Control' => 'max-age=3600',
    'X-Calibre-Auth-Header' => $auth_header,
  ], [ '' ] ];
}

sub login ($self, $req) {
  my %vars = (
    root => $req->base =~ s{/?\z}{/}r,
    url => $req->parameters->get('url'),
    username => $req->env->{'psgix.session'}->{user},
  );

  my $status = 200;

  if ($req->method eq 'POST') {
    my $user = $vars{username} = $req->body_parameters->get('username');
    my $pass = $req->body_parameters->get('password');
    if ($self->check_password($user, $pass, 1)) {
      $req->env->{'psgix.session.options'}->{change_id} = 1;
      $req->env->{'psgix.session'}->{user} = $user;
      $req->env->{'psgix.session'}->{logged_in} = 1;
      return [ 302, [ 'Location' => $self->calibre_root ], [ 'Login success' ] ];
    }
    $vars{username} = $user
      if defined $user;
    $vars{error} = 'Invalid username or password!';
    $status = 401;
  }

  return [
    $status,
    [
      'Content-Type' => 'text/html; charset=UTF-8',
    ],
    [
      $self->render('login.tx', \%vars),
    ]
  ];
}

sub logout ($self, $req) {
  my %vars;

  if ($req->method eq 'POST') {
    $req->env->{'psgix.session'}->{logged_in} = 0;
    return [ 200, [ 'Content-Type' => 'text/plain; charset=UTF-8' ], [ 'Logged out' ] ];
  }

  return [
    200,
    [
      'Content-Type' => 'text/html; charset=UTF-8',
    ],
    [
      $self->render('logout.tx', \%vars),
    ]
  ];
}

sub render ($self, $template, $vars = {}) {
  my $renderer = $self->renderer;
  my %vars = (
    calibre_root => $self->calibre_root,
    %$vars,
  );
  return $renderer->render($template, $vars);
}

if (caller =~ /^Plack::Sandbox::/) {
  return __PACKAGE__->new->to_app;
}

1;

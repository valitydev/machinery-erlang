%%%
%%% Modernizer backend behaviour.
%%%

-module(machinery_modernizer_backend).

%% API
-export([modernize/5]).

%% Behaviour definition

-type namespace() :: machinery:namespace().
-type id() :: machinery:id().
-type range() :: machinery:range().
-type backend_opts() :: machinery:backend_opts(_).

-callback modernize(namespace(), id(), range(), backend_opts()) -> ok | {error, notfound}.

%% API

-type backend() :: module().

-spec modernize(backend(), namespace(), id(), range(), backend_opts()) -> ok | {error, notfound}.
modernize(Backend, Namespace, Id, Range, Opts) ->
    Backend:modernize(Namespace, Id, Range, Opts).

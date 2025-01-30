%%%
%%% Machinery backend behaviour.

-module(machinery_backend).

%% API
-export([start/5]).
-export([call/6]).
-export([repair/6]).
-export([get/5]).
-export([notify/6]).
-export([remove/4]).

%% Behaviour definition

-type namespace() :: machinery:namespace().
-type id() :: machinery:id().
-type range() :: machinery:range().
-type args() :: machinery:args(_).
-type backend_opts() :: machinery:backend_opts(_).

-callback start(namespace(), id(), args(), backend_opts()) -> ok | {error, exists}.

-callback call(namespace(), id(), range(), args(), backend_opts()) -> {ok, machinery:response(_)} | {error, notfound}.

-callback repair(namespace(), id(), range(), args(), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.

-callback get(namespace(), id(), range(), backend_opts()) -> {ok, machinery:machine(_, _)} | {error, notfound}.

-callback notify(namespace(), id(), range(), args(), backend_opts()) -> ok | {error, notfound} | no_return().

-callback remove(namespace(), id(), backend_opts()) -> ok | {error, notfound}.

%% API

-type backend() :: module().

-spec start(backend(), namespace(), id(), args(), backend_opts()) -> ok | {error, exists}.
start(Backend, Namespace, Id, Args, Opts) ->
    Backend:start(Namespace, Id, Args, Opts).

-spec call(backend(), namespace(), id(), range(), args(), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(Backend, Namespace, Id, Range, Args, Opts) ->
    Backend:call(Namespace, Id, Range, Args, Opts).

-spec repair(backend(), namespace(), id(), range(), args(), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(Backend, Namespace, Id, Range, Args, Opts) ->
    Backend:repair(Namespace, Id, Range, Args, Opts).

-spec get(backend(), namespace(), id(), range(), backend_opts()) -> {ok, machinery:machine(_, _)} | {error, notfound}.
get(Backend, Namespace, Id, Range, Opts) ->
    Backend:get(Namespace, Id, Range, Opts).

-spec notify(backend(), namespace(), id(), range(), args(), backend_opts()) -> ok | {error, notfound} | no_return().
notify(Backend, Namespace, Id, Range, Args, Opts) ->
    Backend:notify(Namespace, Id, Range, Args, Opts).

-spec remove(backend(), namespace(), id(), backend_opts()) -> ok | {error, notfound}.
remove(Backend, Namespace, Id, Opts) ->
    Backend:remove(Namespace, Id, Opts).

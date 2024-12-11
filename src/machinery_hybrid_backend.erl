-module(machinery_hybrid_backend).

%% NOTE This module does not implement direct backend callbacks, but
%% only it's client API's functions.
%% Actual backends with dependencies are expected to be implemented,
%% set up and configured in their own ways using their corresponding
%% modules and APIs.

%% Machinery backend
-behaviour(machinery_backend).

-export([start/4]).
-export([call/5]).
-export([repair/5]).
-export([get/4]).
-export([notify/5]).

%% API

-export([new/3]).

%%

-type backend_opts() :: machinery:backend_opts(#{
    primary_backend := machinery:backend(machinery_prg_backend:backend_opts()),
    fallback_backend := machinery:backend(machinery_mg_backend:backend_opts())
}).

%%

-spec new(
    woody_context:ctx(),
    machinery_prg_backend:backend_opts_static(),
    machinery_mg_backend:backend_opts_static()
) -> machinery:backend(backend_opts()).
new(WoodyCtx, ProgressorOpts, MachinegunOpts) ->
    {?MODULE, #{
        primary_backend => machinery_prg_backend:new(WoodyCtx, ProgressorOpts),
        fallback_backend => machinery_mg_backend:new(WoodyCtx, MachinegunOpts)
    }}.

-spec start(machinery:namespace(), machinery:id(), machinery:args(_), backend_opts()) -> ok | {error, exists}.
start(NS, ID, Args, Opts) ->
    call_backend(primary_backend, start, [NS, ID, Args], Opts).

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, Range, Args, Opts) ->
    call_backend_with_fallback(call, [NS, ID, Range, Args], Opts).

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, Range, Args, Opts) ->
    call_backend_with_fallback(repair, [NS, ID, Range, Args], Opts).

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, Opts) ->
    call_backend_with_fallback(get, [NS, ID, Range], Opts).

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, Range, Args, Opts) ->
    call_backend_with_fallback(notify, [NS, ID, Range, Args], Opts).

%%

call_backend_with_fallback(Function, ArgsWithoutOpts, ThisBackendOpts) ->
    case call_backend(primary_backend, Function, ArgsWithoutOpts, ThisBackendOpts) of
        {error, notfound} ->
            call_backend(fallback_backend, Function, ArgsWithoutOpts, ThisBackendOpts);
        Result ->
            Result
    end.

call_backend(WhichBackend, Function, ArgsWithoutOpts, ThisBackendOpts) ->
    {Module, Opts} = maps:get(WhichBackend, ThisBackendOpts),
    erlang:apply(Module, Function, ArgsWithoutOpts ++ [Opts]).

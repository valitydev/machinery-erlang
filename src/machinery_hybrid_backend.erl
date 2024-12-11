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
    %% NOTE Query fallback backend if machine exists; don't query
    %% storage for events for better performance.
    case call_backend(fallback_backend, get, [NS, ID, {undefined, 0, forward}], Opts) of
        {ok, _} ->
            ok = maybe_migrate_machine(NS, ID, Opts),
            {error, exists};
        {error, notfound} ->
            call_backend(primary_backend, start, [NS, ID, Args], Opts)
    end.

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, Range, Args, Opts) ->
    call_backend_and_maybe_migrate(NS, ID, call, [NS, ID, Range, Args], Opts).

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, Range, Args, Opts) ->
    call_backend_and_maybe_migrate(NS, ID, repair, [NS, ID, Range, Args], Opts).

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, Opts) ->
    call_backend_and_maybe_migrate(NS, ID, get, [NS, ID, Range], Opts).

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, Range, Args, Opts) ->
    call_backend_and_maybe_migrate(NS, ID, notify, [NS, ID, Range, Args], Opts).

%%

call_backend_and_maybe_migrate(NS, ID, Function, ArgsWithoutOpts, ThisBackendOpts) ->
    case call_backend(primary_backend, Function, ArgsWithoutOpts, ThisBackendOpts) of
        {error, notfound} ->
            ok = maybe_migrate_machine(NS, ID, ThisBackendOpts),
            call_backend(primary_backend, Function, ArgsWithoutOpts, ThisBackendOpts);
        Result ->
            Result
    end.

call_backend(WhichBackend, Function, ArgsWithoutOpts, ThisBackendOpts) ->
    {Module, Opts} = maps:get(WhichBackend, ThisBackendOpts),
    erlang:apply(Module, Function, ArgsWithoutOpts ++ [Opts]).

maybe_migrate_machine(NS, ID, Opts) ->
    case call_backend(fallback_backend, get, [NS, ID, {undefined, undefined, forward}], Opts) of
        {error, notfound} ->
            ok;
        {ok, #{history := History, aux_state := AuxState, timer := TimestampSec, status := SimpleStatus}} ->
            %% TODO Read events by limited batches to construct complete history
            migrate_machine(NS, ID, History, AuxState, TimestampSec, SimpleStatus, Opts)
    end.

%% FIXME Refactor into smaller funcs
migrate_machine(NS, ID, History, AuxState, TimestampSec, SimpleStatus, Opts) ->
    {_, FallbackOpts} = maps:get(primary_backend, Opts),
    Schema = maps:get(schema, FallbackOpts),
    Version = machinery_mg_schema:get_version(Schema, event),
    SContext = #{
        machine_ns => NS,
        machine_id => ID
    },
    ProcessHistory = lists:map(
        fun({EventID, {DateTime, _Usec}, EventBody}) ->
            {Event, SContext} = machinery_mg_schema:marshal(Schema, {event, Version}, EventBody, SContext),
            #{
                %% FIXME Those fields must not be exposed here!
                %% process_id := id(),
                %% task_id := task_id(),
                event_id => EventID,
                timestamp => genlib_time:daytime_to_unixtime(DateTime),
                metadata => #{<<"format">> => Version},
                payload => machinery_utils:encode(term, Event)
            }
        end,
        History
    ),
    Status =
        case SimpleStatus of
            failed -> <<"error">>;
            working -> <<"running">>;
            undefined -> <<"running">>
        end,
    Action =
        case TimestampSec of
            undefined ->
                undefined;
            _ ->
                #{set_timer => TimestampSec}
        end,
    Req = #{
        ns => NS,
        id => ID,
        %% NOTE This requests' args MUST NOT be encoded into binary
        args => #{
            process => #{
                process_id => ID,
                %% We don't know if it is failed
                status => Status,
                aux_state => machinery_utils:encode(aux_state, AuxState),
                %% TODO Maybe add aux_state format info
                metadata => #{},
                history => ProcessHistory
            },
            action => Action
        },
        context => machinery_utils:encode(
            context, machinery_utils:add_otel_context(maps:with([woody_ctx], FallbackOpts))
        )
    },
    case progressor:put(Req) of
        {ok, _Result} ->
            ok;
        {error, Reason} ->
            %% TODO Add proper error to handle somewhere upward
            erlang:error({machine_migration_failed, Reason})
    end.

-module(machinery_prg_backend).

-include_lib("progressor/include/progressor.hrl").

-export([new/2]).

%% Machinery backend
-behaviour(machinery_backend).

-export([start/4]).
-export([call/5]).
-export([repair/5]).
-export([get/4]).
-export([notify/5]).

%% Progressor processor callback
-export([process/3]).

%% Machine API

-type backend_opts() :: #{
    %% TODO Context?
    %% context := _,
    handler := machinery:logic_handler(_),
    namespace := machinery:namespace()
}.

-type ctx_opts() :: map().

-spec new(woody_context:ctx(), ctx_opts()) -> machinery:backend(ctx_opts()).
new(WoodyCtx, CtxOpts) ->
    {?MODULE, CtxOpts#{woody_ctx => WoodyCtx}}.

-spec start(machinery:namespace(), machinery:id(), machinery:args(_), backend_opts()) -> ok | {error, exists}.
start(NS, ID, Args, CtxOpts) ->
    case progressor:init(make_request(NS, ID, Args, CtxOpts)) of
        {ok, ok} ->
            ok;
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        {error, <<"process is error">>} ->
            erlang:error({failed, NS, ID});
        {error, <<"process already exists">>} ->
            {error, exists}
    end.

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, _Range, Args, CtxOpts) ->
    %% TODO Add history range support
    case progressor:call(make_request(NS, ID, Args, CtxOpts)) of
        {ok, _Result} = Response ->
            Response;
        {error, <<"process not found">>} ->
            {error, notfound};
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        {error, <<"process is error">>} ->
            erlang:error({failed, NS, ID})
    end.

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, _Range, Args, CtxOpts) ->
    %% TODO Add history range support
    case progressor:repair(make_request(NS, ID, Args, CtxOpts)) of
        {ok, {repair_error, Reason}} ->
            {error, {failed, unmarshal(content, Reason)}};
        {ok, _Result} = Response ->
            Response;
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        {error, <<"process not found">>} ->
            {error, notfound};
        {error, <<"process is running">>} ->
            {error, working};
        {error, <<"process is error">>} ->
            erlang:error({failed, NS, ID})
    end.

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, CtxOpts) ->
    RangeArgs = range_args(Range),
    case progressor:get(make_request(NS, ID, RangeArgs, CtxOpts)) of
        {ok, Process} ->
            {ok, unmarshal_process(NS, RangeArgs, Process)};
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        {error, <<"process not found">>} ->
            {error, notfound}
    end.

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, _Range, Args, CtxOpts) ->
    %% TODO Add history range support
    case progressor:notify(make_request(NS, ID, Args, CtxOpts)) of
        {ok, _Response} ->
            ok;
        {error, <<"process not found">>} ->
            {error, notfound};
        %% TODO Impl API
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS})
    end.

%%

range_args(undefined) ->
    #{};
range_args({EventCursor, Limit, _Direction}) ->
    %% Direction always forward?
    #{
        offset => genlib:define(EventCursor, 1) - 1,
        limit => Limit
    }.

specify_range(RangeArgs, Machine = #{history := History}) ->
    HistoryLen = erlang:length(History),
    Offset = maps:get(offset, RangeArgs, 0),
    Limit0 = maps:get(limit, RangeArgs, HistoryLen),
    Limit1 = erlang:min(Limit0, HistoryLen),
    Machine#{range => {Offset, Limit1, forward}}.

make_request(NS, ID, Args, CtxOpts) ->
    #{
        ns => NS,
        id => ID,
        args => marshal(args, Args),
        context => marshal(context, CtxOpts)
    }.

%% Machine's processor callback entrypoint

-type encoded_args() :: binary().
-type encoded_ctx() :: binary().

-spec process({task_t(), encoded_args(), process()}, backend_opts(), encoded_ctx()) -> process_result().
process({CallType, BinArgs, Process}, Opts, BinCtx) ->
    try
        %% TODO Passthrough history range
        Machine = unmarshal_process(maps:get(namespace, Opts), #{}, Process),
        CtxOpts = unmarshal(context, BinCtx),
        Handler = machinery_utils:expand_modopts(maps:get(handler, Opts), #{}),
        handle_result(
            machine_namespace(Machine),
            machine_id(Machine),
            latest_event_id(Machine),
            case CallType of
                init ->
                    Args = unmarshal(args, BinArgs),
                    machinery:dispatch_signal({init, Args}, Machine, Handler, CtxOpts);
                timeout ->
                    %% FIXME Timeout args are unmarshalable '<<>>'
                    machinery:dispatch_signal(timeout, Machine, Handler, CtxOpts);
                notify ->
                    Args = unmarshal(args, BinArgs),
                    machinery:dispatch_signal({notification, Args}, Machine, Handler, CtxOpts);
                call ->
                    Args = unmarshal(args, BinArgs),
                    machinery:dispatch_call(Args, Machine, Handler, CtxOpts);
                repair ->
                    Args = unmarshal(args, BinArgs),
                    machinery:dispatch_repair(Args, Machine, Handler, CtxOpts)
            end
        )
    catch
        Class:Reason:Stacktrace ->
            %% TODO Fail machine/process?
            %% TODO Add logging or span tracing
            %% ct:print("~p~n", [{Class, Reason, Stacktrace}]),
            erlang:raise(Class, Reason, Stacktrace)
    end.

machine_namespace(#{namespace := NS}) ->
    NS.

machine_id(#{id := ID}) ->
    ID.

latest_event_id(#{history := []}) ->
    0;
latest_event_id(#{history := History}) ->
    {LatestEventID, _, _} = lists:last(History),
    LatestEventID.

handle_result(NS, ID, LatestEventID, {error, Reason}) ->
    %% _ = LatestEventID,
    %% {error, marshal(content, {Reason, #{machine_ns => NS, machine_id => ID}})};
    %% TODO Review '{error, Reason}' clause for it is very special and
    %% only for repairing issues.
    %%
    %% Dirty hack with response. However it breaks contract since this
    %% process call MUST NOT produce new effects, state or action!
    PseudoResult = #{},
    Response = {repair_error, marshal(content, {Reason, #{machine_ns => NS, machine_id => ID}})},
    {ok, marshal_result(LatestEventID, Response, PseudoResult, #{})};
handle_result(_NS, _ID, LatestEventID, {ok, {Response, Result}}) ->
    {ok, marshal_result(LatestEventID, Response, Result, #{})};
handle_result(_NS, _ID, LatestEventID, {Response, Result}) ->
    {ok, marshal_result(LatestEventID, Response, Result, #{})};
handle_result(_NS, _ID, LatestEventID, Result) ->
    {ok, marshal_result(LatestEventID, undefined, Result, #{})}.

unmarshal_process(NS, RangeArgs, Process = #{process_id := ID, history := History}) ->
    AuxState = maps:get(aux_state, Process, undefined),
    specify_range(RangeArgs, #{
        namespace => NS,
        id => ID,
        history => unmarshal({list, event}, History),
        aux_state => unmarshal(aux_state, AuxState)
    }).

marshal_result(LatestEventID, Response, Result, Metadata) ->
    Events = maps:get(events, Result, []),
    Actions = maps:get(action, Result, []),
    AuxState = maps:get(aux_state, Result, undefined),
    genlib_map:compact(#{
        events => marshal(event_bodies, {LatestEventID, Events}),
        action => marshal(actions, Actions),
        response => Response,
        aux_state => marshal(aux_state, AuxState),
        metadata => Metadata
    }).

%% TODO Move marshalling utils
%% Marshalling

marshal(timeout, {timeout, V}) ->
    V;
marshal(timeout, {deadline, V}) ->
    genlib_time:daytime_to_unixtime(V) - erlang:system_time(second);
marshal(context, V) ->
    marshal(content, V);
marshal(args, V) ->
    marshal(content, V);
marshal(actions, V) when is_list(V) ->
    lists:foldl(
        fun
            ({set_timer, T}, _) -> #{set_timer => marshal(timeout, T)};
            ({set_timer, T, _R}, _) -> #{set_timer => marshal(timeout, T)};
            %% TODO Handling timeout for timer?
            %% TODO Event range?
            ({set_timer, T, _R, _HT}, _) -> #{set_timer => marshal(timeout, T)};
            %% FIXME Spec '-type action() :: #{set_timer := pos_integer(), remove => true} | unset_timer' lies.
            %% 'set_timer => 1' (or with zero) leads to race condition on removal.
            %% 'set_timer' key must not be present for action to succeed.
            (remove, _) -> #{remove => true};
            (unset_timer, _) -> unset_timer;
            (continue, _) -> #{set_timer => 0};
            (_, A) -> A
        end,
        undefined,
        V
    );
marshal(actions, V) ->
    marshal(actions, [V]);
marshal(event_bodies, {LatestID, Events}) ->
    lists:map(
        fun({ID, Ev}) ->
            #{
                %% FIXME Those fields must not be exposed here!
                %% process_id := id(),
                %% task_id := task_id(),
                event_id => ID,
                timestamp => genlib_time:now(),
                metadata => #{format => 1},
                payload => marshal(content, Ev)
            }
        end,
        lists:zip(lists:seq(LatestID + 1, LatestID + erlang:length(Events)), Events)
    );
marshal(aux_state, V) ->
    marshal(content, V);
marshal(content, undefined) ->
    undefined;
marshal(content, V) ->
    erlang:term_to_binary(V).

unmarshal(context, V) ->
    unmarshal(content, V);
unmarshal(args, V) ->
    unmarshal(content, V);
unmarshal(aux_state, V) ->
    unmarshal(content, V);
unmarshal(event, V) ->
    %% TODO Only '#{metadata := #{format := 1}, ...}' for now
    %% process_id := id(),
    %% task_id := task_id(),
    %% event_id := event_id(),
    %% timestamp := timestamp_sec(),
    %% metadata => #{format => pos_integer()},
    %% payload := binary()
    DateTime = calendar:system_time_to_universal_time(maps:get(timestamp, V), 1),
    {maps:get(event_id, V), {DateTime, 0}, unmarshal(content, maps:get(payload, V))};
unmarshal({list, T}, V) when is_list(V) ->
    lists:map(fun(SV) -> unmarshal(T, SV) end, V);
unmarshal(content, undefined) ->
    undefined;
unmarshal(content, V) ->
    %% Go with stupid simple
    erlang:binary_to_term(V).

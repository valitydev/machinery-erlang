-module(machinery_prg_backend).

-include_lib("progressor/include/progressor.hrl").
-include_lib("opentelemetry_api/include/otel_tracer.hrl").
-include_lib("opentelemetry_api/include/opentelemetry.hrl").

-export([new/2]).

%% Machinery backend
-behaviour(machinery_backend).

-export([start/4]).
-export([call/5]).
-export([repair/5]).
-export([get/4]).
-export([notify/5]).
-export([remove/3]).

%% Progressor processor callback
-export([process/3]).

%% Machine API

-define(BACKEND_CORE_OPTS,
    handler := machinery:logic_handler(_),
    namespace := machinery:namespace(),
    schema := machinery_mg_schema:schema()
).

-type backend_opts_static() :: #{
    ?BACKEND_CORE_OPTS
}.

-export_type([backend_opts/0]).
-export_type([backend_opts_static/0]).

-type backend_opts() :: machinery:backend_opts(#{
    ?BACKEND_CORE_OPTS,
    woody_ctx := woody_context:ctx(),
    otel_ctx => otel_ctx:t()
}).

-ifdef(WITH_OTEL).
-define(WITH_OTEL_SPAN(N, O, F), ?with_span(N, O, F)).
-else.
-define(WITH_OTEL_SPAN(N, O, F), begin
    _ = N,
    %% NOTE Prevents 'a term is constructed, but never used'
    #{} = O,
    F(otel_tracer_noop:noop_span_ctx())
end).
-endif.

-spec new(woody_context:ctx(), backend_opts_static()) -> machinery:backend(backend_opts()).
new(WoodyCtx, Opts) ->
    {?MODULE, Opts#{woody_ctx => WoodyCtx}}.

-spec start(machinery:namespace(), machinery:id(), machinery:args(_), backend_opts()) -> ok | {error, exists}.
start(NS, ID, Args, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"start process">>, SpanOpts, fun(_SpanCtx) ->
        case progressor:init(make_request(NS, ID, Args, CtxOpts)) of
            {ok, ok} ->
                ok;
            {error, <<"namespace not found">>} ->
                erlang:error({namespace_not_found, NS});
            {error, <<"process already exists">>} ->
                {error, exists};
            {error, {exception, _Class, _Reason}} ->
                erlang:error({failed, NS, ID})
        end
    end).

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, _Range, Args, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"call process">>, SpanOpts, fun(_SpanCtx) ->
        %% TODO Add history range support
        case progressor:call(make_request(NS, ID, Args, CtxOpts)) of
            {ok, _Result} = Response ->
                Response;
            {error, <<"process not found">>} ->
                {error, notfound};
            {error, <<"namespace not found">>} ->
                erlang:error({namespace_not_found, NS});
            {error, {exception, _Class, _Reason}} ->
                erlang:error({failed, NS, ID});
            %% NOTE Clause for an error from progressor's internal
            %% process status guard
            {error, <<"process is error">>} ->
                erlang:error({failed, NS, ID});
            {error, _Reason} = Error ->
                %% NOTE Wtf, review specs
                {ok, Error}
        end
    end).

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, _Range, Args, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"repair process">>, SpanOpts, fun(_SpanCtx) ->
        %% TODO Add history range support
        case progressor:repair(make_request(NS, ID, Args, CtxOpts)) of
            {ok, _Result} = Response ->
                Response;
            {error, <<"namespace not found">>} ->
                erlang:error({namespace_not_found, NS});
            {error, <<"process not found">>} ->
                {error, notfound};
            {error, <<"process is running">>} ->
                {error, working};
            {error, {exception, _Class, _Reason}} ->
                erlang:error({failed, NS, ID});
            %% NOTE Clause for an error from progressor's internal
            %% process status guard
            {error, <<"process is error">>} ->
                erlang:error({failed, NS, ID});
            {error, Reason} ->
                {error, {failed, machinery_utils:decode(term, Reason)}}
        end
    end).

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"get process">>, SpanOpts, fun(_SpanCtx) ->
        RangeArgs = range_args(Range),
        case progressor:get(make_request(NS, ID, RangeArgs, CtxOpts)) of
            {ok, Process} ->
                {Machine, _SContext} = unmarshal_process(NS, RangeArgs, Process, get_schema(CtxOpts)),
                {ok, Machine};
            {error, <<"namespace not found">>} ->
                erlang:error({namespace_not_found, NS});
            {error, <<"process not found">>} ->
                {error, notfound}
        end
    end).

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, Range, Args, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"notify process">>, SpanOpts, fun(_SpanCtx) ->
        %% TODO Add history range support
        %% FIXME Temporary pass notify as sync call
        try
            case call(NS, ID, Range, {notify, Args}, CtxOpts) of
                {ok, _} -> ok;
                R -> R
            end
        catch
            error:{failed, _NS, _ID} ->
                %% NOTE Not a 'notify' error
                ok
        end
    end).

-spec remove(machinery:namespace(), machinery:id(), backend_opts()) -> ok | {error, notfound}.
remove(NS, ID, CtxOpts) ->
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"remove process">>, SpanOpts, fun(_SpanCtx) ->
        %% FIXME Temporary pass remove as sync call
        try
            case call(NS, ID, {0, 0, forward}, {remove, #{}}, CtxOpts) of
                {ok, _} -> ok;
                R -> R
            end
        catch
            error:{failed, _NS, _ID} ->
                %% NOTE Not a 'remove' error
                ok
        end
    end).

%%

%% After querying resulting list is expected to be sorted with id
%% values ascending before returning it as events.
range_args(undefined) ->
    range_args({undefined, undefined, forward});
range_args({undefined, Limit, backward}) ->
    %% TODO Support flag for 'ORDER BY' inversion
    maps:put(inverse_order, true, range_args({undefined, Limit, forward}));
range_args({Offset, undefined, backward}) ->
    #{limit => Offset - 1};
range_args({After, Limit, backward}) ->
    range_args({After - Limit - 1, Limit, forward});
range_args({After, Limit, forward}) ->
    genlib_map:compact(#{
        offset => After,
        limit => Limit
    }).

specify_range(RangeArgs, Machine = #{history := History}) ->
    HistoryLen = erlang:length(History),
    Offset = maps:get(offset, RangeArgs, 0),
    Limit0 = maps:get(limit, RangeArgs, HistoryLen),
    Limit1 = erlang:min(Limit0, HistoryLen),
    Machine#{range => {Offset, Limit1, forward}}.

get_namespace(#{namespace := Namespace}) ->
    Namespace.

get_schema(#{schema := Schema}) ->
    Schema.

make_request(NS, ID, Args, CtxOpts) ->
    #{
        ns => NS,
        id => ID,
        args => machinery_utils:encode(args, Args),
        context => machinery_utils:encode(context, machinery_utils:add_otel_context(maps:with([woody_ctx], CtxOpts)))
    }.

build_schema_context(NS, ID) ->
    #{
        machine_ns => NS,
        machine_id => ID
    }.

%% Machine's processor callback entrypoint

-type encoded_args() :: binary().
-type encoded_ctx() :: binary().

-spec process({task_t(), encoded_args(), process()}, backend_opts(), encoded_ctx()) -> process_result().
process({CallType, BinArgs, Process}, Opts, BinCtx) ->
    ProcessCtx = machinery_utils:decode(context, BinCtx),
    ok = machinery_utils:attach_otel_context(ProcessCtx),
    NS = get_namespace(Opts),
    ID = maps:get(process_id, Process),
    SpanOpts = #{kind => ?SPAN_KIND_INTERNAL, attributes => process_tags(NS, ID)},
    ?WITH_OTEL_SPAN(<<"processing">>, SpanOpts, fun(_SpanCtx) ->
        try
            do_process(CallType, BinArgs, Process, Opts, ProcessCtx)
        catch
            Class:Reason:Stacktrace ->
                _ = ?record_exception(Class, Reason, Stacktrace, process_tags(NS, ID)),
                {error, {exception, Class, Reason}}
        end
    end).

do_process(remove, _BinArgs, _Process, _Opts, _ProcessCtx) ->
    %% NOTE Not actually implemented on a client but mocked via 'call'
    {ok,
        genlib_map:compact(#{
            %% TODO Event version?
            events => [],
            action => #{remove => true}
        })};
do_process(CallType, BinArgs, Process, Opts, ProcessCtx) ->
    Schema = get_schema(Opts),
    NS = get_namespace(Opts),
    %% TODO Passthrough history range
    {Machine, SContext} = unmarshal_process(NS, #{}, Process, Schema),
    Handler = machinery_utils:expand_modopts(maps:get(handler, Opts), #{}),
    Result =
        case CallType of
            init ->
                Args = machinery_utils:decode(args, BinArgs),
                machinery:dispatch_signal({init, Args}, Machine, Handler, ProcessCtx);
            timeout ->
                %% FIXME Timeout args are unmarshalable '<<>>'
                machinery:dispatch_signal(timeout, Machine, Handler, ProcessCtx);
            %% NOTE Not actually implemented on a client but mocked via 'call'
            notify ->
                Args = machinery_utils:decode(args, BinArgs),
                machinery:dispatch_signal({notification, Args}, Machine, Handler, ProcessCtx);
            call ->
                case machinery_utils:decode(args, BinArgs) of
                    {notify, Args} ->
                        machinery:dispatch_signal({notification, Args}, Machine, Handler, ProcessCtx);
                    Args ->
                        machinery:dispatch_call(Args, Machine, Handler, ProcessCtx)
                end;
            repair ->
                Args = machinery_utils:decode(args, BinArgs),
                machinery:dispatch_repair(Args, Machine, Handler, ProcessCtx)
        end,
    handle_result(Schema, SContext, latest_event_id(Machine), Result).

latest_event_id(#{history := []}) ->
    0;
latest_event_id(#{history := History}) ->
    {LatestEventID, _, _} = lists:last(History),
    LatestEventID.

handle_result(_Schema, SContext, _LatestEventID, {error, Reason}) ->
    {error, machinery_utils:encode(term, {Reason, SContext})};
handle_result(Schema, SContext, LatestEventID, {ok, {Response, Result}}) ->
    {ok, marshal_result(Schema, SContext, LatestEventID, Response, Result, #{})};
handle_result(Schema, SContext, LatestEventID, {Response, Result}) ->
    {ok, marshal_result(Schema, SContext, LatestEventID, Response, Result, #{})};
handle_result(Schema, SContext, LatestEventID, Result) ->
    {ok, marshal_result(Schema, SContext, LatestEventID, undefined, Result, #{})}.

unmarshal_process(NS, RangeArgs, Process = #{process_id := ID, history := History}, Schema) ->
    SContext0 = build_schema_context(NS, ID),
    AuxState = maps:get(aux_state, Process, undefined),
    MachineProcess = specify_range(RangeArgs, #{
        namespace => NS,
        id => ID,
        history => unmarshal({list, {event, Schema, SContext0}}, History),
        %% TODO AuxState version?
        aux_state => machinery_utils:decode(aux_state, AuxState)
    }),
    {MachineProcess, SContext0}.

marshal_result(Schema, SContext, LatestEventID, Response, Result, Metadata) ->
    Events = maps:get(events, Result, []),
    Actions = maps:get(action, Result, []),
    AuxState = maps:get(aux_state, Result, undefined),
    genlib_map:compact(#{
        %% TODO Event version?
        events => marshal({event_bodies, Schema, SContext}, {LatestEventID, Events}),
        action => marshal(actions, Actions),
        response => Response,
        %% TODO AuxState version?
        aux_state => machinery_utils:encode(aux_state, AuxState),
        metadata => Metadata
    }).

process_tags(Namespace, ID) ->
    #{
        <<"progressor.process.ns">> => Namespace,
        <<"progressor.process.id">> => ID
    }.

%% Marshalling

marshal(timeout, {timeout, V}) when is_integer(V) ->
    erlang:system_time(second) + V;
marshal(timeout, {deadline, {V = {_Date, _Time}, _Micro}}) ->
    genlib_time:daytime_to_unixtime(V);
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
            (continue, _) -> #{set_timer => erlang:system_time(second)};
            (_, A) -> A
        end,
        undefined,
        V
    );
marshal(actions, V) ->
    marshal(actions, [V]);
marshal({event_bodies, Schema, SContext}, {LatestID, Events}) ->
    Version = machinery_mg_schema:get_version(Schema, event),
    lists:map(
        fun({ID, Ev}) ->
            % It is expected that schema doesn't want to save anything in the context here.
            {Event, SContext} = machinery_mg_schema:marshal(Schema, {event, Version}, Ev, SContext),

            #{
                %% FIXME Those fields must not be exposed here!
                %% process_id := id(),
                %% task_id := task_id(),
                event_id => ID,
                timestamp => genlib_time:now(),
                metadata => #{<<"format">> => Version},
                payload => machinery_utils:encode(term, Event)
            }
        end,
        lists:zip(lists:seq(LatestID + 1, LatestID + erlang:length(Events)), Events)
    ).

unmarshal({event, Schema, Context0}, V) ->
    %% TODO Only '#{metadata := #{format := 1}, ...}' for now
    %% process_id := id(),
    %% task_id := task_id(),
    %% event_id := event_id(),
    %% timestamp := timestamp_sec(),
    %% metadata => #{format => pos_integer()},
    %% payload := binary()
    Metadata = maps:get(metadata, V, #{}),
    Version = maps:get(<<"format">>, Metadata, 0),
    Payload0 = maps:get(payload, V),
    Payload1 = machinery_utils:decode(term, Payload0),
    DateTime = calendar:system_time_to_universal_time(maps:get(timestamp, V), 1),
    CreatedAt = {DateTime, 0},
    Context1 = Context0#{created_at => CreatedAt},
    % It is expected that schema doesn't want to save anything in the context here.
    {Payload2, Context1} = machinery_mg_schema:unmarshal(Schema, {event, Version}, Payload1, Context1),
    {maps:get(event_id, V), CreatedAt, Payload2};
unmarshal({list, T}, V) when is_list(V) ->
    [unmarshal(T, SV) || SV <- V].

%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-type testgen() :: {_ID, fun(() -> _)}.
-spec test() -> _.

-spec range_args_test_() -> [testgen()].
range_args_test_() ->
    [
        ?_assertEqual(#{}, range_args(undefined)),
        ?_assertEqual(#{}, range_args({undefined, undefined, forward})),
        ?_assertEqual(#{offset => 0, limit => 42}, range_args({0, 42, forward})),
        ?_assertEqual(#{offset => 42}, range_args({42, undefined, forward})),
        ?_assertEqual(#{limit => 10}, range_args({undefined, 10, forward})),
        ?_assertEqual(#{offset => 42, limit => 10}, range_args({42, 10, forward})),
        ?_assertEqual(#{limit => 10, inverse_order => true}, range_args({undefined, 10, backward})),
        ?_assertEqual(#{limit => 41}, range_args({42, undefined, backward})),
        ?_assertEqual(#{offset => 31, limit => 10}, range_args({42, 10, backward}))
    ].

-endif.

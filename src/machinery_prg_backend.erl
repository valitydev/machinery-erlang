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

-spec new(woody_context:ctx(), backend_opts()) -> machinery:backend(backend_opts()).
new(WoodyCtx, Opts) ->
    {?MODULE, Opts#{woody_ctx => WoodyCtx}}.

-spec start(machinery:namespace(), machinery:id(), machinery:args(_), backend_opts()) -> ok | {error, exists}.
start(NS, ID, Args, Opts) ->
    case progressor:init(make_request(NS, ID, Args, Opts)) of
        {ok, ok} ->
            ok;
        %% TODO Impl API
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        %% TODO Impl API
        {error, <<"process failed">>} ->
            erlang:error({failed, NS, ID});
        {error, <<"process already exists">>} ->
            {error, exists}
    end.

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, _Range, Args, Opts) ->
    %% NOTE Always complete range?
    case progressor:call(make_request(NS, ID, Args, Opts)) of
        {ok, _Result} = Response ->
            Response;
        {error, <<"process not found">>} ->
            {error, notfound};
        {error, <<"process is error">>} ->
            erlang:error({failed, NS, ID})
    end.

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, _Range, Args, Opts) ->
    case progressor:repair(make_request(NS, ID, Args, Opts)) of
        {ok, _Result} = Response ->
            Response;
        %% TODO Impl API
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        %% TODO Impl API
        {error, <<"process failed">>} ->
            erlang:error({failed, NS, ID});
        {error, <<"process not found">>} ->
            {error, notfound};
        {error, <<"process is running">>} ->
            {error, working};
        %% TODO Process repair failure reason?
        {error, <<"process is error">>} ->
            {error, {failed, unknown}}
    end.

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, Opts) ->
    RangeArgs =
        case Range of
            undefined ->
                #{};
            %% Direction always forward
            {EventCursor, Limit, _Direction} ->
                #{
                    offset => genlib:define(EventCursor, 1) - 1,
                    limit => Limit
                }
        end,
    case progressor:get(make_request(NS, ID, RangeArgs, Opts)) of
        {ok, Process} ->
            Machine = specify_range(RangeArgs, #{
                namespace => NS,
                id => ID,
                history => unmarshal({list, event}, maps:get(history, Process)),
                aux_state => unmarshal(aux_state, maps:get(aux_state, Process, undefined))
            }),
            {ok, Machine};
        %% TODO Impl API
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS});
        {error, <<"process not found">>} ->
            {error, notfound}
    end.

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, _Range, Args, Opts) ->
    case progressor:notify(make_request(NS, ID, Args, Opts)) of
        {ok, _Response} ->
            ok;
        {error, <<"process not found">>} ->
            {error, notfound};
        %% TODO Impl API
        {error, <<"namespace not found">>} ->
            erlang:error({namespace_not_found, NS})
    end.

%% Machine's processor callback entrypoint

-type encoded_args() :: binary().
-type encoded_ctx() :: binary().

-spec process({task_t(), encoded_args(), process()}, backend_opts(), encoded_ctx()) -> process_result().
process({CallType, BinArgs, #{process_id := ID, history := History, aux_state := AuxState}}, Opts, Ctx) ->
    Args = unmarshal(args, BinArgs),
    Handler = maps:get(handler, Ctx),
    NS = maps:get(namespace, Ctx),
    Machine = specify_range(#{}, #{
        namespace => NS,
        id => ID,
        history => unmarshal({list, content}, History),
        aux_state => unmarshal(aux_state, AuxState)
    }),
    handle_result(
        case CallType of
            init ->
                machinery:dispatch_signal({init, Args}, Machine, Handler, Opts);
            timeout ->
                machinery:dispatch_signal(timeout, Machine, Handler, Opts);
            notify ->
                machinery:dispatch_signal({notification, Args}, Machine, Handler, Opts);
            call ->
                machinery:dispatch_call(Args, Machine, Handler, Opts);
            repair ->
                machinery:dispatch_repair(Args, Machine, Handler, Opts)
        end
    ).

handle_result({error, Reason}) ->
    %% FIXME or maybe throw?
    {error, Reason};
handle_result({ok, {Response, Result}}) ->
    {ok, marshal_result(Response, Result, #{})};
handle_result({Response, Result}) ->
    {ok, marshal_result(Response, Result, #{})};
handle_result(Result) ->
    {ok, marshal_result(undefined, Result, #{})}.

marshal_result(Response, Result, Metadata) ->
    Events = maps:get(events, Result, []),
    Actions = maps:get(action, Result, []),
    AuxState = maps:get(aux_state, Result, undefined),
    genlib_map:compact(#{
        events => marshal({list, event_body}, Events),
        action => marshal(actions, Actions),
        response => Response,
        aux_state => marshal(aux_state, AuxState),
        metadata => Metadata
    }).

%% TODO Move marshalling utils
%% Marshalling

marshal(context, V) ->
    marshal(content, V);
marshal(args, V) ->
    marshal(content, V);
marshal(actions, V) when is_list(V) ->
    lists:foldl(
        fun
            ({set_timer, T}, _) -> #{set_timer => T};
            ({set_timer, T, _R}, _) -> #{set_timer => T};
            %% TODO Handling timeout for timer?
            %% TODO Event range?
            ({set_timer, T, _R, _HT}, _) -> #{set_timer => T};
            (remove, _) -> #{set_timer => 0, remove => true};
            (unset_timer, _) -> unset_timer;
            (_, A) -> A
        end,
        undefined,
        V
    );
marshal(actions, V) ->
    marshal(actions, [V]);
marshal(event_body, V) ->
    marshal(content, V);
marshal(aux_state, V) ->
    marshal(content, V);
marshal({list, T}, V) when is_list(V) ->
    lists:map(fun(SV) -> marshal(T, SV) end, V);
marshal(content, undefined) ->
    undefined;
marshal(content, V) ->
    erlang:term_to_binary(V).

unmarshal(args, V) ->
    unmarshal(content, V);
unmarshal(aux_state, V) ->
    unmarshal(content, V);
unmarshal(event, V) ->
    unmarshal(content, V);
unmarshal({list, T}, V) when is_list(V) ->
    lists:map(fun(SV) -> unmarshal(T, SV) end, V);
unmarshal(content, undefined) ->
    undefined;
unmarshal(content, V) ->
    %% Go with stupid simple
    erlang:binary_to_term(V).

%%

specify_range(RangeArgs, Machine = #{history := History}) ->
    HistoryLen = erlang:length(History),
    Machine#{
        range => {
            maps:get(offset, RangeArgs, 0),
            erlang:min(maps:get(limit, RangeArgs, HistoryLen), HistoryLen),
            forward
        }
    }.

make_request(NS, ID, Args, Opts) ->
    #{
        ns => NS,
        id => ID,
        args => marshal(args, Args),
        context => marshal(context, Opts)
    }.

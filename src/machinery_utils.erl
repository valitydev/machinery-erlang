-module(machinery_utils).

-include_lib("opentelemetry_api/include/opentelemetry.hrl").

%% Types

-type woody_routes() :: [woody_server_thrift_http_handler:route(_)].
-type woody_handler() :: woody:http_handler(woody:th_handler()).
-type handler(T) :: T.
-type get_woody_handler() :: fun((handler(_), route_opts()) -> woody_handler()).

-type woody_server_config() :: #{
    ip := inet:ip_address(),
    port := inet:port_number(),
    protocol_opts => woody_server_thrift_http_handler:protocol_opts(),
    transport_opts => woody_server_thrift_http_handler:transport_opts()
}.

-type route_opts() :: #{
    event_handler := woody:ev_handler() | [woody:ev_handler()],
    handler_limits => woody_server_thrift_http_handler:handler_limits()
}.

-export_type([woody_server_config/0]).
-export_type([woody_routes/0]).
-export_type([woody_handler/0]).
-export_type([route_opts/0]).
-export_type([handler/1]).
-export_type([get_woody_handler/0]).

%% API

-export([get_handler/1]).
-export([get_backend/1]).
-export([expand_modopts/2]).
-export([woody_child_spec/3]).
-export([get_woody_routes/3]).

-export([encode/2]).
-export([decode/2]).

-export([add_otel_context/1]).
-export([attach_otel_context/1]).

%% API

-spec get_handler(machinery:modopts(Opts)) -> {module(), Opts}.
get_handler(Handler) ->
    expand_modopts(Handler, undefined).

-spec get_backend(machinery:backend(Opts)) -> {module(), Opts}.
get_backend(Backend) ->
    expand_modopts(Backend, #{}).

-spec expand_modopts(machinery:modopts(Opts), Opts) -> {module(), Opts}.
expand_modopts({Mod, Opts}, _) ->
    {Mod, Opts};
expand_modopts(Mod, Opts) ->
    {Mod, Opts}.

-spec woody_child_spec(_Id, woody_routes(), woody_server_config()) -> supervisor:child_spec().
woody_child_spec(Id, Routes, Config) ->
    woody_server:child_spec(Id, Config#{
        %% ev handler for `handlers`, which is `[]`, so this is just to satisfy the spec.
        event_handler => {woody_event_handler_default, #{}},
        handlers => [],
        additional_routes => Routes
    }).

-spec get_woody_routes([handler(_)], get_woody_handler(), route_opts()) -> woody_routes().
get_woody_routes(Handlers, GetHandler, Opts = #{event_handler := _}) ->
    woody_server_thrift_http_handler:get_routes(Opts#{
        handlers => [GetHandler(H, Opts) || H <- Handlers]
    }).

%% Term encoding/decoding

-spec encode(atom(), term()) -> binary().
encode(args, V) ->
    encode(term, V);
encode(context, V) ->
    encode(term, V);
encode(aux_state, V) ->
    encode(term, V);
encode(term, undefined) ->
    undefined;
encode(term, V) ->
    erlang:term_to_binary(V).

-spec decode(atom(), binary()) -> term().
decode(args, V) ->
    decode(term, V);
decode(context, V) ->
    decode(term, V);
decode(aux_state, V) ->
    decode(term, V);
decode(term, undefined) ->
    undefined;
decode(term, V) ->
    erlang:binary_to_term(V).

%% OTEL

-type packed_otel_ctx() :: list().

-spec add_otel_context(map()) -> #{_ => _, otel_ctx := list()}.
add_otel_context(CtxOpts) ->
    CtxOpts#{otel_ctx => pack_otel_stub(otel_ctx:get_current())}.

pack_otel_stub(Ctx) ->
    case otel_tracer:current_span_ctx(Ctx) of
        undefined ->
            [];
        #span_ctx{trace_id = TraceID, span_id = SpanID, trace_flags = TraceFlags} ->
            [trace_id_to_binary(TraceID), span_id_to_binary(SpanID), TraceFlags]
    end.

trace_id_to_binary(TraceID) ->
    {ok, EncodedTraceID} = otel_utils:format_binary_string("~32.16.0b", [TraceID]),
    EncodedTraceID.

span_id_to_binary(SpanID) ->
    {ok, EncodedSpanID} = otel_utils:format_binary_string("~16.16.0b", [SpanID]),
    EncodedSpanID.

-spec attach_otel_context(#{otel_ctx := packed_otel_ctx()}) -> ok.
attach_otel_context(#{otel_ctx := PackedOtelCtx}) ->
    case restore_otel_stub(otel_ctx:get_current(), PackedOtelCtx) of
        NewCtx when map_size(NewCtx) =:= 0 ->
            ok;
        NewCtx ->
            _ = otel_ctx:attach(choose_viable_otel_ctx(NewCtx, otel_ctx:get_current())),
            ok
    end;
attach_otel_context(_) ->
    ok.

%% lowest bit is if it is sampled
-define(IS_NOT_SAMPLED(SpanCtx), SpanCtx#span_ctx.trace_flags band 2#1 =/= 1).

choose_viable_otel_ctx(NewCtx, CurrentCtx) ->
    case {otel_tracer:current_span_ctx(NewCtx), otel_tracer:current_span_ctx(CurrentCtx)} of
        {SpanCtx = #span_ctx{}, #span_ctx{}} when ?IS_NOT_SAMPLED(SpanCtx) -> CurrentCtx;
        {undefined, #span_ctx{}} -> CurrentCtx;
        {_, _} -> NewCtx
    end.

restore_otel_stub(Ctx, [TraceID, SpanID, TraceFlags]) ->
    SpanCtx = otel_tracer:from_remote_span(binary_to_id(TraceID), binary_to_id(SpanID), TraceFlags),
    otel_tracer:set_current_span(Ctx, SpanCtx);
restore_otel_stub(Ctx, _Other) ->
    Ctx.

binary_to_id(Opaque) when is_binary(Opaque) ->
    binary_to_integer(Opaque, 16).

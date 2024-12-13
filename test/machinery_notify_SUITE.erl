-module(machinery_notify_SUITE).

-behaviour(machinery).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

%% Common Tests callbacks
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).

%% Tests

-export([ordinary_notify_test/1]).
-export([unknown_id_notify_test/1]).
-export([unknown_namespace_notify_test/1]).
-export([ranged_notify_test/1]).

%% Machinery callbacks

-export([init/4]).
-export([process_timeout/3]).
-export([process_repair/4]).
-export([process_call/4]).
-export([process_notification/4]).

%% Internal types

-type config() :: ct_helper:config().
-type test_case_name() :: ct_helper:test_case_name().
-type group_name() :: ct_helper:group_name().
-type test_return() :: _ | no_return().

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [
        {group, machinery_mg_backend},
        {group, machinery_prg_backend}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name() | {group, group_name()}]}].
groups() ->
    [
        {machinery_mg_backend, [], [{group, all}]},
        {machinery_prg_backend, [], [{group, all_wo_ranged}]},
        {all, [sequence], [
            ordinary_notify_test,
            unknown_id_notify_test,
            unknown_namespace_notify_test,
            ranged_notify_test
        ]},
        {all_wo_ranged, [sequence], [
            ordinary_notify_test,
            unknown_id_notify_test,
            unknown_namespace_notify_test
            %%, ranged_notify_test
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    {StartedApps, _StartupCtx} = ct_helper:start_apps([machinery]),
    [{started_apps, StartedApps} | C].

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    ok = ct_helper:stop_apps(?config(started_apps, C)),
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(machinery_mg_backend = Name, C0) ->
    C1 = [{backend, Name}, {group_sup, ct_sup:start()} | C0],
    {ok, _Pid} = start_backend(C1),
    C1;
init_per_group(machinery_prg_backend = Name, C0) ->
    %% _ = dbg:tracer(),
    %% _ = dbg:p(all, c),
    %% _ = dbg:tpl({'prg_processor', 'process', '_'}, x),
    %% _ = dbg:tpl({'machinery', 'dispatch_call', '_'}, x),
    %% _ = dbg:tpl({'machinery_prg_backend', 'marshal_result', '_'}, x),
    C1 = [{backend, Name} | C0],
    {NewApps, _} = ct_helper:start_apps([
        epg_connector,
        ct_helper:construct_progressor_config(backend_opts())
    ]),
    lists:keyreplace(started_apps, 1, C1, {started_apps, ?config(started_apps, C1) ++ NewApps});
init_per_group(_Name, C) ->
    C.

-spec end_per_group(group_name(), config()) -> config().
end_per_group(machinery_mg_backend, C) ->
    ok = ct_sup:stop(?config(group_sup, C)),
    C;
end_per_group(machinery_prg_backend, C) ->
    ok = ct_helper:stop_apps([progressor]),
    %% ok = progressor:cleanup(#{ns => namespace()}),
    C;
end_per_group(_Name, C) ->
    C.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(TestCaseName, C) ->
    ct_helper:makeup_cfg([ct_helper:test_case_name(TestCaseName), ct_helper:woody_ctx()], C).

%% Tests

-spec ordinary_notify_test(config()) -> test_return().
ordinary_notify_test(C) ->
    ID = unique(),
    ?assertEqual(ok, start(ID, init_numbers, C)),
    ?assertEqual(ok, notify(ID, do_something, C)),
    _ = timer:sleep(1000),
    {ok, #{history := History}} = get(ID, C),
    ?assertMatch([{_, _, something} | _], lists:reverse(History)).

-spec unknown_id_notify_test(config()) -> test_return().
unknown_id_notify_test(C) ->
    ID = unique(),
    ?assertEqual({error, notfound}, notify(ID, do_something, C)).

-spec unknown_namespace_notify_test(config()) -> test_return().
unknown_namespace_notify_test(C) ->
    ID = unique(),
    ?assertError({namespace_not_found, mmm}, machinery:notify(mmm, ID, do_something, get_backend(C))).

-spec ranged_notify_test(config()) -> test_return().
ranged_notify_test(C) ->
    ID = unique(),
    ?assertEqual(ok, start(ID, init_numbers, C)),
    ?assertEqual(ok, notify(ID, sum_numbers, {10, 9, backward}, C)),
    _ = timer:sleep(1000),
    {ok, #{history := History1}} = get(ID, C),
    ?assertMatch([{_, _, {sum, 45}} | _], lists:reverse(History1)),
    ?assertEqual(ok, notify(ID, sum_numbers, {2, 9, forward}, C)),
    _ = timer:sleep(1000),
    {ok, #{history := History2}} = get(ID, C),
    ?assertMatch([{_, _, {sum, 63}} | _], lists:reverse(History2)).

%% Machinery handler

-type event() :: any().
-type aux_st() :: any().
-type machine() :: machinery:machine(event(), aux_st()).
-type handler_opts() :: machinery:handler_opts(_).
-type result() :: machinery:result(event(), aux_st()).

-spec init(_Args, machine(), undefined, handler_opts()) -> result().
init(init_numbers, _Machine, _, _Opts) ->
    #{
        events => lists:seq(1, 100)
    }.

-spec process_timeout(machine(), undefined, handler_opts()) -> no_return().
process_timeout(#{}, _, _Opts) ->
    erlang:error({not_implemented, process_timeout}).

-spec process_call(_Args, machine(), undefined, handler_opts()) -> no_return().
process_call(_Args, _Machine, _, _Opts) ->
    erlang:error({not_implemented, process_call}).

-spec process_repair(_Args, machine(), undefined, handler_opts()) -> no_return().
process_repair(_Args, _Machine, _, _Opts) ->
    erlang:error({not_implemented, process_repair}).

-spec process_notification(_Args, machine(), undefined, handler_opts()) -> result().
process_notification(do_something, _Machine, _, _Opts) ->
    #{
        events => [something]
    };
process_notification(sum_numbers, #{history := History}, _, _Opts) ->
    EventsSum = lists:foldr(
        fun
            ({_, _, Num}, Acc) when is_number(Num) ->
                Num + Acc;
            ({_, _, _}, Acc) ->
                Acc
        end,
        0,
        History
    ),
    #{
        events => [{sum, EventsSum}]
    }.

%% Helpers

start(ID, Args, C) ->
    machinery:start(namespace(), ID, Args, get_backend(C)).

notify(ID, Args, C) ->
    machinery:notify(namespace(), ID, Args, get_backend(C)).

notify(ID, Args, Range, C) ->
    machinery:notify(namespace(), ID, Range, Args, get_backend(C)).

get(ID, C) ->
    machinery:get(namespace(), ID, get_backend(C)).

namespace() ->
    general.

backend_opts() ->
    #{
        namespace => namespace(),
        handler => ?MODULE,
        schema => machinery_mg_schema_generic
    }.

unique() ->
    genlib:unique().

start_backend(C) ->
    {ok, _PID} = supervisor:start_child(
        ?config(group_sup, C),
        child_spec(C)
    ).

-spec child_spec(config()) -> supervisor:child_spec().
child_spec(C) ->
    child_spec(?config(backend, C), C).

-spec child_spec(atom(), config()) -> supervisor:child_spec().
child_spec(machinery_mg_backend, _C) ->
    BackendConfig = #{
        path => <<"/v1/stateproc">>,
        backend_config => #{
            schema => machinery_mg_schema_generic
        }
    },
    Handler = {?MODULE, BackendConfig},
    Routes = machinery_mg_backend:get_routes(
        [Handler],
        #{event_handler => {woody_event_handler_default, #{}}}
    ),
    ServerConfig = #{
        ip => {0, 0, 0, 0},
        port => 8022
    },
    machinery_utils:woody_child_spec(machinery_mg_backend, Routes, ServerConfig).

-spec get_backend(config()) -> machinery_mg_backend:backend().
get_backend(C) ->
    get_backend(?config(backend, C), C).

-spec get_backend(atom(), config()) -> machinery_mg_backend:backend().
get_backend(machinery_mg_backend, C) ->
    machinery_mg_backend:new(
        ct_helper:get_woody_ctx(C),
        #{
            client => #{
                url => <<"http://machinegun:8022/v1/automaton">>,
                event_handler => {woody_event_handler_default, #{}}
            },
            schema => machinery_mg_schema_generic
        }
    );
get_backend(machinery_prg_backend, C) ->
    machinery_prg_backend:new(ct_helper:get_woody_ctx(C), backend_opts()).

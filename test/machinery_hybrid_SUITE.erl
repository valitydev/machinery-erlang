-module(machinery_hybrid_SUITE).

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
-export([end_per_testcase/2]).

%% Tests

-export([start_notfound_test/1]).
-export([get_notfound_test/1]).
-export([call_notfound_test/1]).
-export([notify_notfound_test/1]).
-export([repair_notfound_test/1]).
-export([remove_notfound_test/1]).

-export([start_existing_test/1]).
-export([get_existing_test/1]).
-export([call_existing_test/1]).
-export([notify_existing_test/1]).
-export([repair_existing_test/1]).
-export([remove_existing_test/1]).

-export([timeout_independent_test/1]).
-export([concurrent_start_with_migration_test/1]).
-export([concurrent_call_with_migration_test/1]).

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

-define(HYBRID, machinery_hybrid_backend).
-define(PRIMARY, machinery_prg_backend).
-define(FALLBACK, machinery_mg_backend).

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [
        {group, ?HYBRID}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name() | {group, group_name()}]}].
groups() ->
    [
        {?HYBRID, [parallel], [
            start_notfound_test,
            get_notfound_test,
            call_notfound_test,
            notify_notfound_test,
            repair_notfound_test,
            remove_notfound_test,

            start_existing_test,
            get_existing_test,
            call_existing_test,
            notify_existing_test,
            repair_existing_test,
            remove_existing_test,

            timeout_independent_test,
            concurrent_start_with_migration_test,
            concurrent_call_with_migration_test
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    {StartedApps, _StartupCtx} = ct_helper:start_apps([machinery, opentelemetry_exporter, opentelemetry]),
    [{started_apps, StartedApps} | C].

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    ok = ct_helper:stop_apps(?config(started_apps, C)),
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(?HYBRID = Name, C0) ->
    C1 = [{backend, Name}, {group_sup, ct_sup:start()} | C0],
    {ok, _Pid} = start_backend(C1),
    {NewApps, _} = ct_helper:start_apps([
        epg_connector,
        ct_helper:construct_progressor_config(backend_opts())
    ]),
    lists:keyreplace(started_apps, 1, C1, {started_apps, ?config(started_apps, C1) ++ NewApps});
init_per_group(_Name, C) ->
    C.

-spec end_per_group(group_name(), config()) -> config().
end_per_group(?HYBRID, C) ->
    ok = ct_sup:stop(?config(group_sup, C)),
    ok = ct_helper:stop_apps([progressor]),
    %% ok = progressor:cleanup(#{ns => namespace()}),
    C;
end_per_group(_Name, C) ->
    C.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(TestCaseName, C) ->
    ct_helper:with_span(
        ?MODULE, TestCaseName, ct_helper:makeup_cfg([ct_helper:test_case_name(TestCaseName), ct_helper:woody_ctx()], C)
    ).

-spec end_per_testcase(test_case_name(), config()) -> ok.
end_per_testcase(_Name, C) ->
    ct_helper:end_span(C).

%% Tests

-spec start_notfound_test(config()) -> test_return().
start_notfound_test(C) ->
    ID = unique(),
    ?assertEqual(ok, start(ID, init_numbers, ?HYBRID, C)),
    ?assertEqual({error, exists}, start(ID, init_numbers, ?PRIMARY, C)),
    ?assertEqual(ok, start(ID, init_numbers, ?FALLBACK, C)).

-spec get_notfound_test(config()) -> test_return().
get_notfound_test(C) ->
    ID = unique(),
    [
        ?assertMatch({error, notfound}, get(ID, B, C))
     || B <- [?PRIMARY, ?FALLBACK, ?HYBRID]
    ].

-spec call_notfound_test(config()) -> test_return().
call_notfound_test(C) ->
    ID = unique(),
    [
        ?assertMatch({error, notfound}, call(ID, do_something, B, C))
     || B <- [?PRIMARY, ?FALLBACK, ?HYBRID]
    ].

-spec notify_notfound_test(config()) -> test_return().
notify_notfound_test(C) ->
    ID = unique(),
    [
        ?assertMatch({error, notfound}, notify(ID, do_something, B, C))
     || B <- [?PRIMARY, ?FALLBACK, ?HYBRID]
    ].

-spec repair_notfound_test(config()) -> test_return().
repair_notfound_test(C) ->
    ID = unique(),
    [
        ?assertMatch({error, notfound}, repair(ID, simple, B, C))
     || B <- [?PRIMARY, ?FALLBACK, ?HYBRID]
    ].

-spec remove_notfound_test(config()) -> test_return().
remove_notfound_test(C) ->
    ID = unique(),
    [
        ?assertMatch({error, notfound}, remove(ID, B, C))
     || B <- [?PRIMARY, ?FALLBACK, ?HYBRID]
    ].

-spec start_existing_test(config()) -> test_return().
start_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertEqual({error, exists}, start(ID, init_numbers, ?HYBRID, C)),
    ?assertMatch({ok, #{}}, get(ID, ?PRIMARY, C)).

-spec get_existing_test(config()) -> test_return().
get_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertMatch({ok, #{}}, get(ID, ?HYBRID, C)),
    ?assertMatch({ok, #{}}, get(ID, ?PRIMARY, C)).

-spec call_existing_test(config()) -> test_return().
call_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertMatch({ok, done}, call(ID, do_something, ?HYBRID, C)),
    ?assertMatch({ok, #{}}, get(ID, ?PRIMARY, C)).

-spec notify_existing_test(config()) -> test_return().
notify_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertEqual(ok, notify(ID, do_something, ?HYBRID, C)),
    %% NOTE Maybe tweak timer or refactor into event occurrence await helper
    _ = timer:sleep(1000),
    {ok, #{history := History}} = get(ID, ?PRIMARY, C),
    ?assertMatch([{_, _, something} | _], lists:reverse(History)).

-spec repair_existing_test(config()) -> test_return().
repair_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertError({failed, general, ID}, call(ID, fail, ?FALLBACK, C)),
    ?assertEqual({ok, done}, repair(ID, simple, ?HYBRID, C)),
    ?assertEqual({ok, lists:seq(1, 100)}, call(ID, get_events, ?PRIMARY, C)).

-spec remove_existing_test(config()) -> test_return().
remove_existing_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    ?assertMatch({error, notfound}, get(ID, ?PRIMARY, C)),
    ?assertMatch({ok, #{}}, get(ID, ?FALLBACK, C)),
    ?assertEqual({error, notfound}, remove(ID, ?HYBRID, C)),
    ?assertMatch({error, notfound}, get(ID, ?FALLBACK, C)).

-spec timeout_independent_test(config()) -> test_return().
timeout_independent_test(C) ->
    ID = unique(),
    ?assertEqual(ok, start(ID, init_timer, ?FALLBACK, C)),
    ?assertEqual(ok, start(ID, init_timer, ?PRIMARY, C)),
    timer:sleep(timer:seconds(5)),
    Expected = lists:seq(1, 10),
    ?assertMatch({ok, #{aux_state := Expected}}, get(ID, ?FALLBACK, C)),
    ?assertMatch({ok, #{aux_state := Expected}}, get(ID, ?PRIMARY, C)).

-spec concurrent_start_with_migration_test(config()) -> test_return().
concurrent_start_with_migration_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    Pids = stage_actors(10, fun() ->
        start(ID, init_numbers, ?HYBRID, C)
    end),
    ok = start_actors(Pids),
    ok = await_actors(Pids, fun({error, exists}) -> ok end),
    ?assertEqual({error, exists}, start(ID, init_numbers, ?HYBRID, C)).

-spec concurrent_call_with_migration_test(config()) -> test_return().
concurrent_call_with_migration_test(C) ->
    ID = existing_only_in_fallback_backend(C),
    Pids = stage_actors(10, fun() ->
        call(ID, do_something, ?HYBRID, C)
    end),
    ok = start_actors(Pids),
    ok = await_actors(Pids, fun({ok, done}) -> ok end),
    ?assertMatch({ok, done}, call(ID, do_something, ?HYBRID, C)).

%% Machinery handler

-type event() :: any().
-type aux_st() :: any().
-type machine() :: machinery:machine(event(), aux_st()).
-type handler_opts() :: machinery:handler_opts(_).
-type result() :: machinery:result(event(), aux_st()).
-type response() :: machinery:response(_).
-type error() :: machinery:error(_).

-spec init(_Args, machine(), undefined, handler_opts()) -> result().
init(init_timer, _Machine, _, _Opts) ->
    #{
        events => lists:seq(1, 10),
        action => {set_timer, {timeout, 0}}
    };
init(init_numbers, _Machine, _, _Opts) ->
    #{
        events => lists:seq(1, 100)
    }.

-spec process_timeout(machine(), undefined, handler_opts()) -> result().
process_timeout(#{history := History}, _, _Opts) ->
    Bodies = lists:map(fun({_ID, _CreatedAt, Body}) -> Body end, History),
    #{
        events => [timer_fired],
        % why not
        action => unset_timer,
        aux_state => Bodies
    }.

-spec process_call(_Args, machine(), undefined, handler_opts()) -> {response(), result()}.
process_call(do_something, _Machine, _, _Opts) ->
    {done, #{
        events => [1, yet_another_event],
        aux_state => <<>>
    }};
process_call(get_events, #{history := History}, _, _Opts) ->
    Bodies = lists:map(fun({_ID, _CreatedAt, Body}) -> Body end, History),
    {Bodies, #{}};
process_call(remove, _Machine, _, _Opts) ->
    {removed, #{action => [remove]}};
process_call(fail, _Machine, _, _Opts) ->
    erlang:error(fail).

-spec process_repair(_Args, machine(), undefined, handler_opts()) -> {ok, {response(), result()}} | {error, error()}.
process_repair(simple, _Machine, _, _Opts) ->
    {ok, {done, #{}}};
process_repair({add_events, Events}, _Machine, _, _Opts) ->
    {ok, {done, #{events => Events}}};
process_repair(count_events, #{history := History}, _, _Opts) ->
    {ok, {done, #{events => [{count_events, erlang:length(History)}]}}};
process_repair(fail, _Machine, _, _Opts) ->
    {error, fail};
process_repair(unexpected_fail, _Machine, _, _Opts) ->
    erlang:error(unexpected_fail).

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

stage_actors(Quantity, Fun) when Quantity > 0 ->
    [
        spawn(fun() ->
            receive
                {start, From} ->
                    From ! {result, self(), Fun()}
            end
        end)
     || _I <- lists:seq(1, Quantity)
    ].

start_actors(Pids) ->
    lists:foreach(fun(Pid) -> Pid ! {start, self()} end, Pids).

await_actors(Pids, MatchFun) ->
    lists:foreach(
        fun(Pid) ->
            receive
                {result, Pid, Result} ->
                    MatchFun(Result)
            after 5_000 ->
                erlang:error(timeout)
            end
        end,
        Pids
    ).

existing_only_in_fallback_backend(C) ->
    ID = unique(),
    ok = start(ID, init_numbers, ?FALLBACK, C),
    ID.

start(ID, Args, Backend, C) ->
    machinery:start(namespace(), ID, Args, get_backend(Backend, C)).

get(ID, Backend, C) ->
    machinery:get(namespace(), ID, get_backend(Backend, C)).

call(ID, Args, Backend, C) ->
    machinery:call(namespace(), ID, Args, get_backend(Backend, C)).

%% TODO Tests w/ range
%% call(ID, Args, Range, Backend, C) ->
%%     machinery:call(namespace(), ID, Range, Args, get_backend(Backend, C)).

notify(ID, Args, Backend, C) ->
    machinery:notify(namespace(), ID, Args, get_backend(Backend, C)).

%% TODO Tests w/ range
%% notify(ID, Args, Range, Backend, C) ->
%%     machinery:notify(namespace(), ID, Range, Args, get_backend(Backend, C)).

repair(ID, Args, Backend, C) ->
    machinery:repair(namespace(), ID, Args, get_backend(Backend, C)).

%% TODO Tests w/ range
%% repair(ID, Args, Range, Backend, C) ->
%%     machinery:repair(namespace(), ID, Range, Args, get_backend(Backend, C)).

remove(ID, Backend, C) ->
    machinery:remove(namespace(), ID, get_backend(Backend, C)).

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
    {ok, _Pid} = supervisor:start_child(
        ?config(group_sup, C),
        child_spec(C)
    ).

-spec child_spec(config()) -> supervisor:child_spec().
child_spec(C) ->
    child_spec(?FALLBACK, C).

-spec child_spec(atom(), config()) -> supervisor:child_spec().
child_spec(?FALLBACK, _C) ->
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
    machinery_utils:woody_child_spec(?FALLBACK, Routes, ServerConfig).

-spec get_backend(atom(), config()) -> machinery_mg_backend:backend().
get_backend(?HYBRID, C) ->
    machinery_hybrid_backend:new(ct_helper:get_woody_ctx(C), backend_opts(), #{
        client => #{
            url => <<"http://machinegun:8022/v1/automaton">>,
            event_handler => {woody_event_handler_default, #{}}
        },
        schema => machinery_mg_schema_generic
    });
get_backend(?FALLBACK, C) ->
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
get_backend(?PRIMARY, C) ->
    machinery_prg_backend:new(ct_helper:get_woody_ctx(C), backend_opts()).

%%% TODO
%%%  - Model things like `ct_sup` with something hook-like?

-module(machinery_machine_unique_tag_mg_example_test_SUITE).

%% Test suite

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).

-export([tag_success/1]).
-export([tag_twice_success/1]).
-export([single_tag_set_only/1]).
-export([untag_success/1]).
-export([conflict_untag_failure/1]).
-export([reset_tag_success/1]).
-export([tag_unset_timely/1]).

-import(ct_helper, [
    cfg/2,
    start_apps/1,
    get_woody_ctx/1
]).

%%

-type config() :: ct_helper:config().
-type test_case_name() :: ct_helper:test_case_name().
-type group_name() :: ct_helper:group_name().
-type test_return() :: _ | no_return().

-spec all() -> [test_case_name() | {group, group_name()}].
all() ->
    [
        tag_success,
        tag_twice_success,
        single_tag_set_only,
        untag_success,
        conflict_untag_failure,
        reset_tag_success,
        tag_unset_timely
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    % _ = dbg:tracer(),
    % _ = dbg:p(all, c),
    % _ = dbg:tpl({'woody_client', '_', '_'}, x),
    {StartedApps, _StartupCtx} = start_apps([machinery]),
    SuiteSup = ct_sup:start(),
    start_woody_server([
        {started_apps, StartedApps},
        {suite_sup, SuiteSup}
        | C
    ]).

start_woody_server(C) ->
    {ok, Pid} = supervisor:start_child(
        cfg(suite_sup, C),
        machinery_machine_unique_tag_mg_example:child_spec(?MODULE)
    ),
    [{payproc_mg_machine_sup, Pid} | C].

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    ok = ct_sup:stop(cfg(suite_sup, C)),
    ok = ct_helper:stop_apps(cfg(started_apps, C)),
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(TestCaseName, C) ->
    ct_helper:makeup_cfg([ct_helper:test_case_name(TestCaseName), ct_helper:woody_ctx()], C).

%%

-spec tag_success(config()) -> test_return().
tag_success(C) ->
    Tag = genlib:unique(),
    ID = pid_to_binary(self()),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    {ok, ID} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts).

-spec tag_twice_success(config()) -> test_return().
tag_twice_success(C) ->
    Tag = genlib:unique(),
    ID = pid_to_binary(self()),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    {ok, ID} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts).

-spec single_tag_set_only(config()) -> test_return().
single_tag_set_only(C) ->
    Tag = genlib:unique(),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    IDs = [integer_to_binary(E) || E <- lists:seq(1, 42)],
    Rs = genlib_pmap:map(
        fun(ID) ->
            {ID, machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts)}
        end,
        IDs
    ),
    [IDSet] = [ID0 || {ID0, ok} <- Rs],
    IDsLeft = IDs -- [IDSet],
    IDsLeft = [ID0 || {ID0, {error, {set, ID}}} <- Rs, ID == IDSet].

-spec untag_success(config()) -> test_return().
untag_success(C) ->
    Tag = genlib:unique(),
    ID = pid_to_binary(self()),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    ok = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID, Opts),
    {error, unset} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts).

-spec conflict_untag_failure(config()) -> test_return().
conflict_untag_failure(C) ->
    Tag = genlib:unique(),
    ID1 = pid_to_binary(self()),
    ID2 = pid_to_binary(cfg(suite_sup, C)),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID1, Opts),
    {error, {set, ID1}} = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID2, Opts),
    ok = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID1, Opts),
    ok = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID2, Opts).

-spec reset_tag_success(config()) -> test_return().
reset_tag_success(C) ->
    Tag = genlib:unique(),
    ID = pid_to_binary(self()),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    ok = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID, Opts),
    ok = machinery_machine_unique_tag_mg_example:untag(example, Tag, ID, Opts),
    ok = machinery_machine_unique_tag_mg_example:tag(example, Tag, ID, Opts),
    {ok, ID} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts).

-spec tag_unset_timely(config()) -> test_return().
tag_unset_timely(C) ->
    Tag = genlib:unique(),
    ID = pid_to_binary(self()),
    Opts = #{woody_ctx => get_woody_ctx(C)},
    ok = machinery_machine_unique_tag_mg_example:tag_until(example, Tag, ID, {timeout, 1}, Opts),
    {ok, ID} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts),
    % twice as much as needed
    ok = timer:sleep(2 * 1000),
    {error, unset} = machinery_machine_unique_tag_mg_example:get(example, Tag, Opts).

%%

pid_to_binary(Pid) ->
    list_to_binary(pid_to_list(Pid)).

-module(machinery_prg_backend).

-include_lib("mg_proto/include/mg_proto_state_processing_thrift.hrl").
-include_lib("progressor/include/progressor.hrl").

%% Machinery backend
-behaviour(machinery_backend).

-export([start/4]).
-export([call/5]).
-export([repair/5]).
-export([get/4]).
-export([notify/5]).

%%
-type backend_opts() :: map().

-spec start(machinery:namespace(), machinery:id(), machinery:args(_), backend_opts()) -> ok | {error, exists}.
start(NS, ID, Args, Opts) ->
    %% Client = get_client(Opts),
    %% Schema = get_schema(Opts),
    %% SContext0 = build_schema_context(NS, ID),
    %% {InitArgs, _SContext1} = marshal({schema, Schema, {args, init}, SContext0}, Args),
    %% case machinery_mg_client:start(marshal(namespace, NS), marshal(id, ID), InitArgs, Client) of
    %%     {ok, ok} ->
    %%         ok;
    %%     {exception, #mg_stateproc_MachineAlreadyExists{}} ->
    %%         {error, exists};
    %%     {exception, #mg_stateproc_NamespaceNotFound{}} ->
    %%         error({namespace_not_found, NS});
    %%     {exception, #mg_stateproc_MachineFailed{}} ->
    %%         error({failed, NS, ID})
    %% end.
    _ = Args,
    _ = Opts,
    error({failed, NS, ID}).

-spec call(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, notfound}.
call(NS, ID, Range, Args, Opts) ->
    %% Client = get_client(Opts),
    %% Schema = get_schema(Opts),
    %% SContext0 = build_schema_context(NS, Id),
    %% Descriptor = {NS, Id, Range},
    %% {CallArgs, SContext1} = marshal({schema, Schema, {args, call}, SContext0}, Args),
    %% case machinery_mg_client:call(marshal(descriptor, Descriptor), CallArgs, Client) of
    %%     {ok, Response0} ->
    %%         {Response1, _SContext2} = unmarshal({schema, Schema, {response, call}, SContext1}, Response0),
    %%         {ok, Response1};
    %%     {exception, #mg_stateproc_MachineNotFound{}} ->
    %%         {error, notfound};
    %%     {exception, #mg_stateproc_NamespaceNotFound{}} ->
    %%         error({namespace_not_found, NS});
    %%     {exception, #mg_stateproc_MachineFailed{}} ->
    %%         error({failed, NS, Id})
    %% end.
    _ = Range,
    _ = Args,
    _ = Opts,
    error({failed, NS, ID}).

-spec repair(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    {ok, machinery:response(_)} | {error, {failed, machinery:error(_)} | notfound | working}.
repair(NS, ID, Range, Args, Opts) ->
    %% Client = get_client(Opts),
    %% Schema = get_schema(Opts),
    %% SContext0 = build_schema_context(NS, Id),
    %% Descriptor = {NS, Id, Range},
    %% {RepairArgs, SContext1} = marshal({schema, Schema, {args, repair}, SContext0}, Args),
    %% case machinery_mg_client:repair(marshal(descriptor, Descriptor), RepairArgs, Client) of
    %%     {ok, Response0} ->
    %%         {Response1, _SContext2} = unmarshal({schema, Schema, {response, {repair, success}}, SContext1}, Response0),
    %%         {ok, Response1};
    %%     {exception, #mg_stateproc_RepairFailed{reason = Reason}} ->
    %%         {error, {failed, unmarshal({schema, Schema, {response, {repair, failure}}, SContext1}, Reason)}};
    %%     {exception, #mg_stateproc_MachineNotFound{}} ->
    %%         {error, notfound};
    %%     {exception, #mg_stateproc_MachineAlreadyWorking{}} ->
    %%         {error, working};
    %%     {exception, #mg_stateproc_NamespaceNotFound{}} ->
    %%         error({namespace_not_found, NS});
    %%     {exception, #mg_stateproc_MachineFailed{}} ->
    %%         error({failed, NS, Id})
    %% end.
    _ = Range,
    _ = Args,
    _ = Opts,
    error({failed, NS, ID}).

-spec get(machinery:namespace(), machinery:id(), machinery:range(), backend_opts()) ->
    {ok, machinery:machine(_, _)} | {error, notfound}.
get(NS, ID, Range, Opts) ->
    %% Client = get_client(Opts),
    %% Schema = get_schema(Opts),
    %% Descriptor = {NS, Id, Range},
    %% case machinery_mg_client:get_machine(marshal(descriptor, Descriptor), Client) of
    %%     {ok, Machine0} ->
    %%         {Machine1, _Context} = unmarshal({machine, Schema}, Machine0),
    %%         {ok, Machine1};
    %%     {exception, #mg_stateproc_MachineNotFound{}} ->
    %%         {error, notfound};
    %%     {exception, #mg_stateproc_NamespaceNotFound{}} ->
    %%         error({namespace_not_found, NS})
    %% end.
    _ = ID,
    _ = Range,
    _ = Opts,
    error({namespace_not_found, NS}).

-spec notify(machinery:namespace(), machinery:id(), machinery:range(), machinery:args(_), backend_opts()) ->
    ok | {error, notfound} | no_return().
notify(NS, ID, Range, Args, Opts) ->
    %% Client = get_client(Opts),
    %% Schema = get_schema(Opts),
    %% SContext0 = build_schema_context(NS, Id),
    %% Descriptor = {NS, Id, Range},
    %% {NotificationArgs, _SContext1} = marshal({schema, Schema, {args, notification}, SContext0}, Args),
    %% case machinery_mg_client:notify(marshal(descriptor, Descriptor), NotificationArgs, Client) of
    %%     {ok, _Response0} ->
    %%         %% Response contains the notification id but it's not like we can do anything with that information
    %%         ok;
    %%     {exception, #mg_stateproc_MachineNotFound{}} ->
    %%         {error, notfound};
    %%     {exception, #mg_stateproc_NamespaceNotFound{}} ->
    %%         error({namespace_not_found, NS})
    %% end.
    _ = ID,
    _ = Range,
    _ = Args,
    _ = Opts,
    error({namespace_not_found, NS}).

%%

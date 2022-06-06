%%%
%%% Modernizer API abstraction.
%%% Behaviour and API.
%%%

-module(machinery_modernizer).

% API
-type namespace() :: machinery:namespace().
-type id() :: machinery:id().
-type range() :: machinery:range().
-type backend() :: machinery:backend(_).

-export([modernize/3]).
-export([modernize/4]).

%% API

-spec modernize(namespace(), id(), backend()) -> ok | {error, notfound}.
modernize(NS, Id, Backend) ->
    modernize(NS, Id, {undefined, undefined, forward}, Backend).

-spec modernize(namespace(), id(), range(), backend()) -> ok | {error, notfound}.
modernize(NS, Id, Range, Backend) ->
    {Module, Opts} = machinery_utils:get_backend(Backend),
    machinery_modernizer_backend:modernize(Module, NS, Id, Range, Opts).

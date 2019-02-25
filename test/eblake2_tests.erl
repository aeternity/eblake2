%%%=============================================================================
%%% @copyright (C) 2019, Hans Svensson
%%% @doc
%%%   Unit tests for the eblake2 module
%%%
%%% @end
%%%=============================================================================
-module(eblake2_tests).
-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

blake2b_test_() ->
    {"Tests for BLAKE2b hash implementation",
     [ fun() -> blake2b(TC) end || TC <- filter_test_vectors(<<"blake2b">>) ]}.

blake2b(_TC = #{in := Msg, key := Key, out := ExpectedOut}) ->
    ?assertEqual(eblake2:blake2b(byte_size(ExpectedOut), Msg, Key), {ok, ExpectedOut}).

blake2s_test_() ->
    {"Tests for BLAKE2s hash implementation",
     [ fun() -> blake2s(TC) end || TC <- filter_test_vectors(<<"blake2s">>) ]}.

blake2s(_TC = #{in := Msg, key := Key, out := ExpectedOut}) ->
    ?assertEqual(eblake2:blake2s(byte_size(ExpectedOut), Msg, Key), {ok, ExpectedOut}).

benchmark_test() ->
    %% Benchmark Blake2b against enacl.
    #{in := In, key := <<>>, out := Exp} = hd(filter_test_vectors(<<"blake2b">>)),
    HashLen = byte_size(Exp),
    {T1, _} = timer:tc(fun() -> [ {ok, Exp} = enacl:generichash(HashLen, In) || _ <- lists:seq(1, 500) ] end),
    {T2, _} = timer:tc(fun() -> [ {ok, Exp} = eblake2:blake2b(HashLen, In) || _ <- lists:seq(1, 500) ] end),

    ?debugFmt("~.2f ms compared to ~.2f ms\n", [T1 / 1000, T2 / 1000]),

    BigData = <<0:(1024*10)>>,

    {T3, _} = timer:tc(fun() -> [ {ok, _} = enacl:generichash(HashLen, BigData) || _ <- lists:seq(1, 50) ] end),
    {T4, _} = timer:tc(fun() -> [ {ok, _} = eblake2:blake2b(HashLen, BigData) || _ <- lists:seq(1, 50) ] end),

    ?debugFmt("~.2f ms compared to ~.2f ms\n", [T3 / 1000, T4 / 1000]),

    ok.

random_test_() ->
    {generator, fun() ->
      [ {lists:concat(["Random test ", I]), fun() -> random_test(I) end} || I <- lists:seq(1, 50) ]
    end}.

random_test(I) ->
    Data = crypto:strong_rand_bytes(I * 50),
    {ok, Enacl}  = enacl:generichash(64, Data),
    {ok, Eblake} = eblake2:blake2b(64, Data),

    ?assertEqual(Eblake, Enacl).
%% Helper functions
test_vectors() ->
    parse_test_vectors("test/blake2_testvectors.json").

parse_test_vectors(File) ->
    {ok, Bin} = file:read_file(File),
    Vectors = jsx:decode(Bin, [{labels, atom}, return_maps]),
    HexToBin = fun(<<>>) -> <<>>;
                  (HexStrBin) ->
                   Size = byte_size(HexStrBin) div 2,
                   <<(binary_to_integer(HexStrBin, 16)):Size/unit:8>>
               end,
    FixBin = fun(TC = #{ in := In0, key := Key0, out := Out0 }) ->
                TC#{ in  := HexToBin(In0),
                     key := HexToBin(Key0),
                     out := HexToBin(Out0) }
             end,
    lists:map(FixBin, Vectors).

filter_test_vectors(Algo) ->
    [ X || X = #{ hash := Algo1 } <- test_vectors(), Algo == Algo1 ].

-endif.



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
    {T1, _} = timer:tc(fun() -> [ Exp = enacl:generichash(HashLen, In) || _ <- lists:seq(1, 500) ] end),
    {T2, _} = timer:tc(fun() -> [ {ok, Exp} = eblake2:blake2b(HashLen, In) || _ <- lists:seq(1, 500) ] end),

    ?debugFmt("~.2f ms compared to ~.2f ms\n", [T1 / 1000, T2 / 1000]),

    BigData = <<0:(1024*10)>>,

    {T3, _} = timer:tc(fun() -> [ enacl:generichash(HashLen, BigData) || _ <- lists:seq(1, 50) ] end),
    {T4, _} = timer:tc(fun() -> [ {ok, _} = eblake2:blake2b(HashLen, BigData) || _ <- lists:seq(1, 50) ] end),

    ?debugFmt("~.2f ms compared to ~.2f ms\n", [T3 / 1000, T4 / 1000]),

    ok.

random_test_() ->
    {generator, fun() ->
      [ {lists:concat(["Random test ", I]), fun() -> random_test(I) end} || I <- lists:seq(1, 50) ]
    end}.

random_test(I) ->
    Data = crypto:strong_rand_bytes(I * 50),
    Enacl  = enacl:generichash(64, Data),
    {ok, Eblake} = eblake2:blake2b(64, Data),

    ?assertEqual(Eblake, Enacl).

hmac_blake2b_test_() ->
    {"Tests for BLAKE2b HMAC implementation",
     [ fun() -> hmac_blake2b(TC) end || TC <- hmac_testcases(blake2b) ]}.

hmac_blake2s_test_() ->
    {"Tests for BLAKE2s HMAC implementation",
     [ fun() -> hmac_blake2s(TC) end || TC <- hmac_testcases(blake2s) ]}.

hmac_blake2b({Key, Data, HMAC}) ->
    ?assertEqual(HMAC, eblake2:hmac(blake2b, Key, Data)).

hmac_blake2s({Key, Data, HMAC}) ->
    ?assertEqual(HMAC, eblake2:hmac(blake2s, Key, Data)).

hex_to_bin(<<>>) ->
    <<>>;
hex_to_bin(HexStrBin) ->
    Size = byte_size(HexStrBin) div 2,
    <<(binary_to_integer(HexStrBin, 16)):Size/unit:8>>.

hmac_testcases(Algo) ->
    [ {hex_to_bin(list_to_binary(K)), hex_to_bin(list_to_binary(D)), H}
      || {{K, D}, H} <- lists:zip(blake2_hmac_key_data(), blake2_hmac_hmac(Algo)) ].

%% Helper functions
test_vectors() ->
    parse_test_vectors("test/blake2_testvectors.json").

parse_test_vectors(File) ->
    {ok, Bin} = file:read_file(File),
    Vectors = jsx:decode(Bin, [{labels, atom}, return_maps]),
    FixBin = fun(TC = #{ in := In0, key := Key0, out := Out0 }) ->
                TC#{ in  := hex_to_bin(In0),
                     key := hex_to_bin(Key0),
                     out := hex_to_bin(Out0) }
             end,
    lists:map(FixBin, Vectors).

filter_test_vectors(Algo) ->
    [ X || X = #{ hash := Algo1 } <- test_vectors(), Algo == Algo1 ].

blake2_hmac_key_data() ->
    [ {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
       "4869205468657265"}
    , {"4a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f"}
    , {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
    , {"0102030405060708090a0b0c0d0e0f10111213141516171819",
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}
    , {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"}
    , {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"}
    , {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"}
    , {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"}
    ].

blake2_hmac_hmac(blake2b) ->
    [ <<53,138,106,24,73,36,137,79,195,75,238,86,128,238,223,87,216,74,55,187,56,131,47,40,142,59,39,220,99,169,140,200,201,30,118,218,71,107,80,139,198,178,212,8,162,72,133,116,82,144,110,74,32,180,140,107,75,85,210,223,15,225,221,36>>
    , <<111,248,132,248,221,194,166,88,107,60,152,164,205,110,189,241,78,193,2,4,182,113,0,115,235,88,101,173,227,122,38,67,184,128,124,19,53,209,7,236,219,159,254,174,182,130,140,70,37,186,23,44,102,55,158,252,210,34,194,222,17,114,122,180>>
    , <<244,59,198,44,122,153,53,60,59,44,96,232,239,36,251,189,66,233,84,120,102,220,156,91,228,237,198,244,167,212,188,10,198,32,194,198,0,52,208,64,240,219,175,134,249,233,205,120,145,160,149,89,94,237,85,226,169,150,33,95,12,21,192,24>>
    , <<229,219,182,222,47,238,66,161,202,160,110,78,123,132,206,64,143,250,92,74,157,226,99,46,202,118,156,222,136,117,1,76,114,208,114,15,234,245,63,118,230,161,128,53,127,82,141,123,244,132,250,58,20,232,204,31,15,59,173,167,23,180,52,145>>
    , <<165,75,41,67,178,162,2,39,212,28,164,108,9,69,175,9,188,31,174,251,47,73,137,76,35,174,188,85,127,183,156,72,137,220,167,68,8,220,134,80,134,102,122,237,238,74,49,133,197,58,73,200,11,129,76,76,88,19,234,12,139,56,168,248>>
    , <<180,214,140,139,182,82,151,170,52,132,168,110,29,51,183,138,70,159,33,234,170,158,212,218,159,236,145,218,71,23,34,61,44,15,163,134,170,47,209,241,255,207,89,23,178,103,84,96,53,237,48,238,164,178,19,162,133,148,211,211,169,179,140,170>>
    , <<171,52,121,128,166,75,94,130,93,209,14,125,50,253,67,160,26,142,109,234,38,122,185,173,125,145,53,36,82,102,24,146,83,17,175,188,176,196,149,25,203,235,221,112,149,64,168,215,37,251,145,26,194,174,233,178,163,170,67,215,150,18,51,147>>
    , <<97,220,242,140,166,12,169,92,130,89,147,39,171,215,169,161,152,111,242,219,211,199,73,69,198,227,35,186,203,76,159,26,94,103,82,93,20,186,141,98,36,177,98,229,102,23,21,37,83,3,69,169,178,86,8,178,125,251,163,180,146,115,213,6>>
    ];
blake2_hmac_hmac(blake2s) ->
    [ <<101,168,183,197,204,145,54,212,36,232,44,55,226,112,126,116,233,19,192,101,91,153,199,95,64,237,243,135,69,58,50,96>>
    , <<144,182,40,30,47,48,56,201,5,106,240,180,167,231,99,202,230,254,93,158,180,56,106,14,201,82,55,137,12,16,79,240>>
    , <<252,196,245,149,41,80,46,52,195,216,218,63,253,171,130,150,106,44,182,55,255,94,155,215,1,19,92,46,148,105,231,144>>
    , <<70,68,52,220,190,206,9,93,69,106,29,98,214,236,86,248,152,230,37,163,158,92,82,189,249,77,175,17,27,173,131,170>>
    , <<210,61,121,57,79,83,213,54,160,150,230,81,68,71,238,170,187,5,222,208,27,227,44,25,55,218,106,143,113,3,188,78>>
    , <<92,76,83,46,110,69,89,83,133,78,21,16,149,38,110,224,127,213,88,129,190,223,139,57,8,217,95,13,190,54,159,234>>
    , <<203,96,246,167,145,241,64,191,138,162,229,31,243,88,205,178,204,92,3,51,4,91,127,183,122,186,122,179,176,207,178,55>>
    , <<190,53,233,217,99,171,215,108,1,184,171,181,22,36,240,209,16,96,16,92,213,22,16,58,114,241,117,214,211,189,30,202>>
    ].

-endif.



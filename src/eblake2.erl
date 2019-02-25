%%%=============================================================================
%%% @copyright (C) 2019, Hans Svensson
%%% @doc
%%%  BLAKE2 implementation in Erlang - for details see: https://blake2.net
%%% @end
%%%=============================================================================
-module(eblake2).

%% API exports
-export([ blake2b/2
        , blake2b/3
        , blake2s/2
        , blake2s/3
        , hmac/3
        ]).

-define(MAXINT_32, 16#FFFFffff).
-define(MAXINT_64, 16#FFFFffffFFFFffff).

%%====================================================================
%% API functions
%%====================================================================
-spec blake2b(HashLen :: integer(), Msg :: binary()) -> {ok, binary()}.
blake2b(HashLen, Msg) ->
    blake2b(HashLen, Msg, <<>>).

-spec blake2b(HashLen :: integer(), Msg :: binary(), Key :: binary()) -> {ok, binary()}.
blake2b(HashLen, Msg0, Key) ->
    %% If message should be keyed, prepend message with padded key.
    Msg = <<(pad(128, Key))/binary, Msg0/binary>>,

    %% Set up the initial state
    Init  = (16#01010000 + (byte_size(Key) bsl 8) + HashLen),
    <<H0:64, H1_7/binary>> = blake2b_iv(),
    H = <<(H0 bxor Init):64, H1_7/binary>>,

    %% Perform the compression - message will be chopped into 128-byte chunks.
    State = blake2b_compress(H, Msg, 0),

    %% Just return the requested part of the hash
    {ok, binary_part(to_little_endian(64, State), {0, HashLen})}.

-spec blake2s(HashLen :: integer(), Msg :: binary()) -> {ok, binary()}.
blake2s(HashLen, Msg) ->
    blake2s(HashLen, Msg, <<>>).

-spec blake2s(HashLen :: integer(), Msg :: binary(), Key :: binary()) -> {ok, binary()}.
blake2s(HashLen, Msg0, Key) ->
    %% If message should be keyed, prepend message with padded key.
    Msg = <<(pad(64, Key))/binary, Msg0/binary>>,

    %% Set up the initial state
    Init  = (16#01010000 + (byte_size(Key) bsl 8) + HashLen),
    <<H0:32, H1_7/binary>> = blake2s_iv(),
    H = <<(H0 bxor Init):32, H1_7/binary>>,

    %% Perform the compression - message will be chopped into 64-byte chunks.
    State = blake2s_compress(H, Msg, 0),

    %% Just return the requested part of the hash
    {ok, binary_part(to_little_endian(32, State), {0, HashLen})}.

-spec hmac(Hash :: blake2b | blake2s, Key :: binary(), Data :: binary()) -> {ok, binary()}.
hmac(blake2b, Key, Data) ->
    hmac(128, fun(D) -> {ok, H} = blake2b(64, D), H end, Key, Data);
hmac(blake2s, Key, Data) ->
    hmac(64, fun(D) -> {ok, H} = blake2s(32, D), H end, Key, Data).


%%====================================================================
%% Internal functions
%%====================================================================
%%

%% Blake2b
blake2b_compress(H, <<Chunk:(128*8), Rest/binary>>, BCompr) when Rest /= <<>> ->
    H1 = blake2b_compress(H, <<Chunk:(128*8)>>, BCompr + 128, false),
    blake2b_compress(H1, Rest, BCompr + 128);
blake2b_compress(H, SmallChunk, BCompr) ->
    Size    = byte_size(SmallChunk),
    FillSize = (128 - Size) * 8,
    blake2b_compress(H, <<SmallChunk/binary, 0:FillSize>>, BCompr + Size, true).

blake2b_compress(H, Chunk0, BCompr, Last) ->
    Chunk = to_big_endian(64, Chunk0),
    <<V0_11:(12*64), V12:64, V13:64, V14:64, V15:64>> = <<H/binary, (blake2b_iv())/binary>>,
    V12_ = V12 bxor (BCompr band ?MAXINT_64),
    V13_ = V13 bxor ((BCompr bsr 64) band ?MAXINT_64),
    V14_ = case Last of
               false -> V14;
               true  -> V14 bxor ?MAXINT_64
           end,
    V = <<V0_11:(12*64), V12_:64, V13_:64, V14_:64, V15:64>>,

    <<VLow:(8*64), VHigh:(8*64)>> =
        lists:foldl(fun(Round, Vx) -> blake2b_mix(Round, Chunk, Vx) end, V, lists:seq(0, 11)),

  <<HInt:(8*64)>> = H,
  <<((HInt bxor VLow) bxor VHigh):(8*64)>>.

blake2b_mix(Rnd, Chunk, V) ->
    <<V0:64, V1:64, V2:64, V3:64, V4:64, V5:64, V6:64, V7:64, V8:64,
      V9:64, V10:64, V11:64, V12:64, V13:64, V14:64, V15:64>> = V,
    <<M0:64, M1:64, M2:64, M3:64, M4:64, M5:64, M6:64, M7:64, M8:64,
      M9:64, M10:64, M11:64, M12:64, M13:64, M14:64, M15:64>> = Chunk,
    Ms = {M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15},
    {S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15} = sigma(Rnd rem 10, Ms),

    {Vx0, Vx4, Vx8,  Vx12} = blake2b_mix(V0, V4, V8,  V12, S0, S1),
    {Vx1, Vx5, Vx9,  Vx13} = blake2b_mix(V1, V5, V9,  V13, S2, S3),
    {Vx2, Vx6, Vx10, Vx14} = blake2b_mix(V2, V6, V10, V14, S4, S5),
    {Vx3, Vx7, Vx11, Vx15} = blake2b_mix(V3, V7, V11, V15, S6, S7),

    {Vy0, Vy5, Vy10, Vy15} = blake2b_mix(Vx0, Vx5, Vx10, Vx15, S8,  S9),
    {Vy1, Vy6, Vy11, Vy12} = blake2b_mix(Vx1, Vx6, Vx11, Vx12, S10, S11),
    {Vy2, Vy7, Vy8,  Vy13} = blake2b_mix(Vx2, Vx7, Vx8,  Vx13, S12, S13),
    {Vy3, Vy4, Vy9,  Vy14} = blake2b_mix(Vx3, Vx4, Vx9,  Vx14, S14, S15),

    <<Vy0:64, Vy1:64, Vy2:64, Vy3:64, Vy4:64, Vy5:64, Vy6:64, Vy7:64, Vy8:64,
      Vy9:64, Vy10:64, Vy11:64, Vy12:64, Vy13:64, Vy14:64, Vy15:64>>.

blake2b_mix(Va, Vb, Vc, Vd, X, Y) ->
    Va1 = (Va + Vb + X) band ?MAXINT_64,
    Vd1 = rotr64(32, Vd bxor Va1),

    Vc1 = (Vc + Vd1) band ?MAXINT_64,
    Vb1 = rotr64(24, Vb bxor Vc1),

    Va2 = (Va1 + Vb1 + Y) band ?MAXINT_64,
    Vd2 = rotr64(16, Va2 bxor Vd1),

    Vc2 = (Vc1 + Vd2) band ?MAXINT_64,
    Vb2 = rotr64(63, Vb1 bxor Vc2),

    {Va2, Vb2, Vc2, Vd2}.

blake2b_iv() ->
    IV0 = 16#6A09E667F3BCC908,
    IV1 = 16#BB67AE8584CAA73B,
    IV2 = 16#3C6EF372FE94F82B,
    IV3 = 16#A54FF53A5F1D36F1,
    IV4 = 16#510E527FADE682D1,
    IV5 = 16#9B05688C2B3E6C1F,
    IV6 = 16#1F83D9ABFB41BD6B,
    IV7 = 16#5BE0CD19137E2179,
    <<IV0:64, IV1:64, IV2:64, IV3:64, IV4:64, IV5:64, IV6:64, IV7:64>>.

sigma(0, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    { E0,  E1,  E2,  E3,  E4,  E5,  E6,  E7,  E8,  E9, E10, E11, E12, E13, E14, E15};
sigma(1, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    {E14, E10,  E4,  E8,  E9, E15, E13,  E6,  E1, E12,  E0,  E2, E11,  E7,  E5,  E3};
sigma(2, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    {E11,  E8, E12,  E0,  E5,  E2, E15, E13, E10, E14,  E3,  E6,  E7,  E1,  E9,  E4};
sigma(3, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    { E7,  E9,  E3,  E1, E13, E12, E11, E14,  E2,  E6,  E5, E10,  E4,  E0, E15,  E8};
sigma(4, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    { E9,  E0,  E5,  E7,  E2,  E4, E10, E15, E14,  E1, E11, E12,  E6,  E8,  E3, E13};
sigma(5, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    { E2, E12,  E6, E10,  E0, E11,  E8,  E3,  E4, E13,  E7,  E5, E15, E14,  E1,  E9};
sigma(6, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    {E12,  E5,  E1, E15, E14, E13,  E4, E10,  E0,  E7,  E6,  E3,  E9,  E2,  E8, E11};
sigma(7, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    {E13, E11,  E7, E14, E12,  E1,  E3,  E9,  E5,  E0, E15,  E4,  E8,  E6,  E2, E10};
sigma(8, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    { E6, E15, E14,  E9, E11,  E3,  E0,  E8, E12,  E2, E13,  E7,  E1,  E4, E10,  E5};
sigma(9, {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15}) ->
    {E10,  E2,  E8,  E4,  E7,  E6,  E1,  E5, E15, E11,  E9, E14,  E3, E12, E13,  E0}.

rotr64(N, I64) ->
    <<I64rot:64>> = rotr641(N, <<I64:64>>),
    I64rot.

rotr641(16, <<X:(64-16), Y:16>>) -> <<Y:16, X:(64-16)>>;
rotr641(24, <<X:(64-24), Y:24>>) -> <<Y:24, X:(64-24)>>;
rotr641(32, <<X:(64-32), Y:32>>) -> <<Y:32, X:(64-32)>>;
rotr641(63, <<X:(64-63), Y:63>>) -> <<Y:63, X:(64-63)>>.


%% Blake2s
blake2s_iv() ->
    IV0 = 16#6A09E667, IV1 = 16#BB67AE85,
    IV2 = 16#3C6EF372, IV3 = 16#A54FF53A,
    IV4 = 16#510E527F, IV5 = 16#9B05688C,
    IV6 = 16#1F83D9AB, IV7 = 16#5BE0CD19,
    <<IV0:32, IV1:32, IV2:32, IV3:32, IV4:32, IV5:32, IV6:32, IV7:32>>.

blake2s_compress(H, <<Chunk:(64*8), Rest/binary>>, BCompr) when Rest /= <<>> ->
    H1 = blake2s_compress(H, <<Chunk:(64*8)>>, BCompr + 64, false),
    blake2s_compress(H1, Rest, BCompr + 64);
blake2s_compress(H, SmallChunk, BCompr) ->
    Size    = byte_size(SmallChunk),
    FillSize = (64 - Size) * 8,
    blake2s_compress(H, <<SmallChunk/binary, 0:FillSize>>, BCompr + Size, true).

blake2s_compress(H, Chunk0, BCompr, Last) ->
    Chunk = to_big_endian(32, Chunk0),
    <<V0_11:(12*32), V12:32, V13:32, V14:32, V15:32>> = <<H/binary, (blake2s_iv())/binary>>,
    V12_ = V12 bxor (BCompr band ?MAXINT_32),
    V13_ = V13 bxor ((BCompr bsr 32) band ?MAXINT_32),
    V14_ = case Last of
               false -> V14;
               true  -> V14 bxor ?MAXINT_32
           end,
    V = <<V0_11:(12*32), V12_:32, V13_:32, V14_:32, V15:32>>,

    <<VLow:(8*32), VHigh:(8*32)>> =
        lists:foldl(fun(Round, Vx) -> blake2s_mix(Round, Chunk, Vx) end, V, lists:seq(0, 9)),

  <<HInt:(8*32)>> = H,
  <<((HInt bxor VLow) bxor VHigh):(8*32)>>.

blake2s_mix(Rnd, Chunk, V) ->
    <<V0:32, V1:32, V2:32, V3:32, V4:32, V5:32, V6:32, V7:32, V8:32,
      V9:32, V10:32, V11:32, V12:32, V13:32, V14:32, V15:32>> = V,
    <<M0:32, M1:32, M2:32, M3:32, M4:32, M5:32, M6:32, M7:32, M8:32,
      M9:32, M10:32, M11:32, M12:32, M13:32, M14:32, M15:32>> = Chunk,
    Ms = {M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15},

    {S0, S1, S2, S3, S4, S5, S6, S7,
     S8, S9, S10, S11, S12, S13, S14, S15} = sigma(Rnd rem 10, Ms),

    {Vx0, Vx4, Vx8,  Vx12} = blake2s_mix(V0, V4, V8,  V12, S0, S1),
    {Vx1, Vx5, Vx9,  Vx13} = blake2s_mix(V1, V5, V9,  V13, S2, S3),
    {Vx2, Vx6, Vx10, Vx14} = blake2s_mix(V2, V6, V10, V14, S4, S5),
    {Vx3, Vx7, Vx11, Vx15} = blake2s_mix(V3, V7, V11, V15, S6, S7),

    {Vy0, Vy5, Vy10, Vy15} = blake2s_mix(Vx0, Vx5, Vx10, Vx15, S8,  S9),
    {Vy1, Vy6, Vy11, Vy12} = blake2s_mix(Vx1, Vx6, Vx11, Vx12, S10, S11),
    {Vy2, Vy7, Vy8,  Vy13} = blake2s_mix(Vx2, Vx7, Vx8,  Vx13, S12, S13),
    {Vy3, Vy4, Vy9,  Vy14} = blake2s_mix(Vx3, Vx4, Vx9,  Vx14, S14, S15),


    <<Vy0:32, Vy1:32, Vy2:32, Vy3:32, Vy4:32, Vy5:32, Vy6:32, Vy7:32, Vy8:32,
      Vy9:32, Vy10:32, Vy11:32, Vy12:32, Vy13:32, Vy14:32, Vy15:32>>.

blake2s_mix(Va, Vb, Vc, Vd, X, Y) ->
    Va1 = (Va + Vb + X) band ?MAXINT_32,
    Vd1 = rotr32(16, Vd bxor Va1),

    Vc1 = (Vc + Vd1) band ?MAXINT_32,
    Vb1 = rotr32(12, Vb bxor Vc1),

    Va2 = (Va1 + Vb1 + Y) band ?MAXINT_32,
    Vd2 = rotr32(8, Va2 bxor Vd1),

    Vc2 = (Vc1 + Vd2) band ?MAXINT_32,
    Vb2 = rotr32(7, Vb1 bxor Vc2),

    {Va2, Vb2, Vc2, Vd2}.

rotr32(N, I32) ->
    <<I32rot:32>> = rotr321(N, <<I32:32>>),
    I32rot.

rotr321(16, <<X:(32-16), Y:16>>) -> <<Y:16, X:(32-16)>>;
rotr321(12, <<X:(32-12), Y:12>>) -> <<Y:12, X:(32-12)>>;
rotr321(8,  <<X:(32-8), Y:8>>)   -> <<Y:8, X:(32-8)>>;
rotr321(7,  <<X:(32-7), Y:7>>)   -> <<Y:7, X:(32-7)>>.

pad(N, Bin) ->
    case (N - (byte_size(Bin) rem N)) rem N of
        0   -> Bin;
        Pad -> <<Bin/binary, 0:(Pad *8)>>
    end.

to_big_endian(X, Bin) -> to_big_endian(X, Bin, <<>>).
to_big_endian(_X, <<>>, Acc) -> Acc;
to_big_endian(X, Bin, Acc) ->
    <<UIntX:X/little-unsigned-integer, Rest/binary>> = Bin,
    to_big_endian(X, Rest, <<Acc/binary, UIntX:X/big-unsigned-integer>>).

to_little_endian(X, Bin) -> to_little_endian(X, Bin, <<>>).
to_little_endian(_X, <<>>, Acc) -> Acc;
to_little_endian(X, Bin, Acc) ->
    <<UIntX:X/big-unsigned-integer, Rest/binary>> = Bin,
    to_little_endian(X, Rest, <<Acc/binary, UIntX:X/little-unsigned-integer>>).

%% HMAC
hmac(BLen, HFun, Key, Data) ->
    Block1 = hmac_format_key(HFun, Key, 16#36, BLen),
    Hash1 = HFun(<<Block1/binary, Data/binary>>),
    Block2 = hmac_format_key(HFun, Key, 16#5C, BLen),
    HFun(<<Block2/binary, Hash1/binary>>).

hmac_format_key(HFun, Key0, Pad, BLen) ->
    Key1 =
        case byte_size(Key0) =< BLen of
            true  -> Key0;
            false -> HFun(Key0)
        end,
    Key2 = pad(Key1, BLen, 0),
    <<PadWord:32>> = <<Pad:8, Pad:8, Pad:8, Pad:8>>,
    << <<(Word bxor PadWord):32>> || <<Word:32>> <= Key2 >>.

pad(Data, MinSize, PadByte) ->
    case byte_size(Data) of
        N when N >= MinSize ->
            Data;
        N ->
            PadData = << <<PadByte:8>> || _ <- lists:seq(1, MinSize - N) >>,
            <<Data/binary, PadData/binary>>
    end.


-module(certinfo).

%% API exports
-export([main/1]).

-include_lib("public_key/include/public_key.hrl").

%%====================================================================
%% API functions
%%====================================================================

%% escript Entry point
main([Host]) ->
    main([Host, "443"]);
main([Host, Port0]) ->
    application:ensure_all_started(ssl),
    Port = erlang:list_to_integer(Port0),
    {ok, SSLSocket} = ssl:connect(Host, Port, []),
    {ok, DERCert} = ssl:peercert(SSLSocket),
    OTPCert = public_key:pkix_decode_cert(DERCert, otp),
    Cert = OTPCert#'OTPCertificate'.tbsCertificate,
    Extensions = Cert#'OTPTBSCertificate'.extensions,
    Validity = Cert#'OTPTBSCertificate'.validity,
    NotBefore = str2datetime(Validity#'Validity'.notBefore),
    NotAfter = str2datetime(Validity#'Validity'.notAfter),
    io:format("Not valid before: ~s~n", [datetime2str(NotBefore)]),
    io:format("Not valid after: ~s~n", [datetime2str(NotAfter)]),
    SAN = lists:keyfind({2, 5, 29, 17}, 2, Extensions),
    Names = lists:map(fun({dNSName, Name}) -> Name end, SAN#'Extension'.extnValue),
    io:format("~nSubject names:~n"),
    lists:foldl(
        fun(N, Acc) ->
            io:format(" ~3b: ~ts~n", [Acc, N]),
            Acc + 1
        end,
        1,
        Names
    ),
    erlang:halt(0).

%%====================================================================
%% Internal functions
%%====================================================================

int_at(S, N) ->
    erlang:list_to_integer(lists:sublist(S, N, 2)).

str2datetime({utcTime, S}) ->
    {
        {
            2000 + int_at(S, 1),
            int_at(S, 3),
            int_at(S, 5)
        },
        {
            int_at(S, 7),
            int_at(S, 9),
            int_at(S, 11)
        }
    }.

datetime2str({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    io_lib:format("~b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b UTC", [
        Year, Month, Day, Hour, Minute, Second
    ]).

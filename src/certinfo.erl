-module(certinfo).

%% API exports
-export([main/1]).

-include_lib("public_key/include/public_key.hrl").

%%====================================================================
%% API functions
%%====================================================================

%% escript Entry point
main([]) ->
    io:format("usage: certinfo hostname [port]~n");
main([Host]) ->
    main([Host, "443"]);
main([Host, Port0]) ->
    application:ensure_all_started(ssl),
    Port = erlang:list_to_integer(Port0),
    case ssl:connect(Host, Port, [{verify, verify_none}], 10_000) of
        {ok, SSLSocket} ->
            {ok, DERCert} = ssl:peercert(SSLSocket),
            OTPCert = public_key:pkix_decode_cert(DERCert, otp),
            Cert = OTPCert#'OTPCertificate'.tbsCertificate,
            Algo = OTPCert#'OTPCertificate'.signatureAlgorithm,
            {HashName, CryptoName} = public_key:pkix_sign_types(
                Algo#'SignatureAlgorithm'.algorithm
            ),
            io:format("Algorithm:~n  ~s ~s~n~n", [
                string:to_upper(atom_to_list(HashName)),
                string:to_upper(atom_to_list(CryptoName))
            ]),
            Extensions = Cert#'OTPTBSCertificate'.extensions,
            Validity = Cert#'OTPTBSCertificate'.validity,
            NotBefore = str2datetime(Validity#'Validity'.notBefore),
            TimeSince = time_diff(NotBefore),
            NotAfter = str2datetime(Validity#'Validity'.notAfter),
            InTime = time_diff(NotAfter),
            io:format("Validity:~n"),
            io:format("  Start: ~-32s (~s local time).~n", [TimeSince, datetime2str(NotBefore)]),
            io:format("  End:   ~-32s (~s local time).~n", [InTime, datetime2str(NotAfter)]),
            SAN = lists:keyfind(?'id-ce-subjectAltName', 2, Extensions),
            Names = lists:map(fun({dNSName, Name}) -> Name end, SAN#'Extension'.extnValue),
            io:format("~nSubject names:~n"),
            lists:foldl(
                fun(N, Acc) ->
                    io:format(" ~3b: ~ts~n", [Acc, N]),
                    Acc + 1
                end,
                1,
                Names
            );
        {error, Err} ->
            io:format("Connection failed: ~p~n", [Err])
    end,
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

datetime2str(UT) ->
    LT = calendar:universal_time_to_local_time(UT),
    {{Year, Month, Day}, {Hour, Minute, Second}} = LT,
    io_lib:format("~b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b", [
        Year, Month, Day, Hour, Minute, Second
    ]).

time_diff(UT) ->
    Then = calendar:datetime_to_gregorian_seconds(UT),
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    {Days, {H, M, S}} = calendar:seconds_to_daystime(abs(Now - Then)),
    Format =
        case Now > Then of
            true -> "~b days and ~b:~2..0b:~2..0b hours ago";
            false -> "in ~b days and ~b:~2..0b:~2..0b hours"
        end,
    io_lib:format(Format, [Days, H, M, S]).

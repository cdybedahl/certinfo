-module(certinfo).

%% API exports
-export([main/1]).
-export([process/2]).

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
    process(Host, Port),
    erlang:halt(0).

process(Host, Port) ->
    case ssl:connect(Host, Port, [{verify, verify_none}], 10_000) of
        {ok, SSLSocket} ->
            io:setopts([{encoding, unicode}]),
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
            print_extensions(Extensions),
            Validity = Cert#'OTPTBSCertificate'.validity,
            Issuer = Cert#'OTPTBSCertificate'.issuer,
            NotBefore = str2datetime(Validity#'Validity'.notBefore),
            TimeSince = time_diff(NotBefore),
            NotAfter = str2datetime(Validity#'Validity'.notAfter),
            InTime = time_diff(NotAfter),
            print_issuer(Issuer),
            io:format("Validity:~n"),
            io:format("  Start: ~-32s (~s local time).~n", [TimeSince, datetime2str(NotBefore)]),
            io:format("  End:   ~-32s (~s local time).~n", [InTime, datetime2str(NotAfter)]),
            SAN = lists:keyfind(?'id-ce-subjectAltName', 2, Extensions),
            Names = lists:map(fun({dNSName, Name}) -> Name end, SAN#'Extension'.extnValue),
            io:format("~nSubject names:~n"),
            lists:foldl(
                fun(N, Acc) ->
                    io:format(" ~3b: ~ts~n", [Acc, maybe_decode(N)]),
                    Acc + 1
                end,
                1,
                Names
            );
        {error, Err} ->
            io:format("Connection failed: ~p~n", [Err])
    end,
    ok.

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

print_issuer({rdnSequence, Sequence}) ->
    io:format(
        "Issuer: ~ts~n~n",
        [lists:join(", ", [rdnvalue_to_string(S) || S <- Sequence])]
    ).

rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 3}, {_, CommonName}}]) ->
    io_lib:format("CN=~ts", [CommonName]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 6}, Country}]) ->
    io_lib:format("Country=~ts", [Country]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 7}, {_, Locality}}]) ->
    io_lib:format("Locality=~ts", [Locality]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 8}, {_, StateOrProvince}}]) ->
    io_lib:format("State=~ts", [StateOrProvince]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 10}, {_, Organization}}]) ->
    io_lib:format("O=~ts", [Organization]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 11}, {_, OrganizationalUnit}}]) ->
    io_lib:format("OU=~ts", [OrganizationalUnit]);
rdnvalue_to_string([{'AttributeTypeAndValue', OID, Data}]) ->
    io_lib:format("~tp=~tp", [OID, Data]).

maybe_decode(N) ->
    case string:find(N, "xn--") of
        nomatch ->
            N;
        _ ->
            [idna:decode(N), " (", N, ")"]
    end.

print_extensions(Extensions) ->
    io:format("Extensions:~n"),
    lists:foreach(fun print_extension/1, Extensions),
    io:format("~n~n").

print_extension(#'Extension'{extnID = ?'id-pe-authorityInfoAccess', extnValue = _ExtnValue}) ->
    io:format("\tAuthority Info Access.~n", []);
print_extension(#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, extnValue = _ExtnValue}) ->
    io:format("\tSignedCertificateTimestampList.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-basicConstraints', extnValue = ExtnValue}) ->
    io:format("\tBasic constraints: "),
    io:format(" CA ~p. ", [ExtnValue#'BasicConstraints'.cA]),
    case ExtnValue#'BasicConstraints'.pathLenConstraint of
        asn1_NOVALUE -> io:format("No path length constraint.~n");
        Val -> io:format("Path length constraint: ~tp~n", [Val])
    end;
print_extension(#'Extension'{extnID = ?'id-ce-certificatePolicies', extnValue = _ExtnValue}) ->
    io:format("\tCertificate policies.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-cRLDistributionPoints', extnValue = _ExtnValue}) ->
    io:format("\tCRL distribution points.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-extKeyUsage', extnValue = ExtnValue}) ->
    io:format("\tExtended key usage: ~ts~n", [lists:join(", ", [oid2str(E) || E <- ExtnValue])]);
print_extension(#'Extension'{extnID = ?'id-ce-keyUsage', extnValue = ExtnValue}) ->
    io:format("\tKey Usage: ~ts~n", [lists:join(", ", [erlang:atom_to_list(E) || E <- ExtnValue])]);
print_extension(#'Extension'{extnID = ?'id-ce-authorityKeyIdentifier'}) ->
    io:format("\tAuthority Key Identifier.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-subjectKeyIdentifier'}) ->
    io:format("\tSubject Key Identifier.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-subjectAltName'}) ->
    io:format("\tSubject alternative names (see below for list).~n", []);
print_extension(E) ->
    io:format("\t~tp~n", [E#'Extension'.extnID]).

oid2str({1, 3, 6, 1, 5, 5, 7, 3, 1}) -> "id-kp-serverAuth";
oid2str({1, 3, 6, 1, 5, 5, 7, 3, 2}) -> "id-kp-clientAuth";
oid2str(OID) -> io_lib:format("~tp", [OID]).

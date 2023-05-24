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
            Serial = Cert#'OTPTBSCertificate'.serialNumber,
            Subject = Cert#'OTPTBSCertificate'.subject,
            {HashName, CryptoName} = public_key:pkix_sign_types(
                Algo#'SignatureAlgorithm'.algorithm
            ),
            io:format("Serial number: 0x~.16B~n", [Serial]),
            io:format("Algorithm: ~s ~s~n~n", [
                string:to_upper(atom_to_list(HashName)),
                string:to_upper(atom_to_list(CryptoName))
            ]),
            Extensions = Cert#'OTPTBSCertificate'.extensions,
            Validity = Cert#'OTPTBSCertificate'.validity,
            Issuer = Cert#'OTPTBSCertificate'.issuer,
            NotBefore = str2datetime(Validity#'Validity'.notBefore),
            TimeSince = time_diff(NotBefore),
            NotAfter = str2datetime(Validity#'Validity'.notAfter),
            InTime = time_diff(NotAfter),
            print_rdn("Subject", Subject),
            print_rdn("Issuer", Issuer),
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
            ),
            print_extensions(Extensions);
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

print_rdn(Name, {rdnSequence, Sequence}) ->
    io:format(
        "~s: ~ts~n~n",
        [Name, lists:join(", ", [rdnvalue_to_string(S) || S <- Sequence])]
    ).

rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-commonName', {_, CommonName}}]) ->
    io_lib:format("CN=~ts", [CommonName]);
rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-countryName', Country}]) ->
    io_lib:format("Country=~ts", [Country]);
rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-localityName', {_, Locality}}]) ->
    io_lib:format("Locality=~ts", [Locality]);
rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-stateOrProvinceName', {_, StateOrProvince}}]) ->
    io_lib:format("State=~ts", [StateOrProvince]);
rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-organizationName', {_, Organization}}]) ->
    io_lib:format("O=~ts", [Organization]);
rdnvalue_to_string([{'AttributeTypeAndValue', ?'id-at-serialNumber', SerialNumber}]) ->
    io_lib:format("Serial=~ts", [SerialNumber]);
rdnvalue_to_string([{'AttributeTypeAndValue', {2, 5, 4, 15}, Category}]) ->
    io_lib:format("Category=~ts", [Category]);
rdnvalue_to_string([
    {'AttributeTypeAndValue', {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}, JurisdictionState}
]) ->
    io_lib:format("JurisdictionState=~ts", [JurisdictionState]);
rdnvalue_to_string([
    {'AttributeTypeAndValue', {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, JurisdictionCountry}
]) ->
    io_lib:format("JurisdictionCountry=~ts", [JurisdictionCountry]);
rdnvalue_to_string([
    {'AttributeTypeAndValue', ?'id-at-organizationalUnitName', {_, OrganizationalUnit}}
]) ->
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
    io:format("~nExtensions:~n"),
    lists:foreach(fun print_extension/1, Extensions),
    io:format("~n").

print_extension(#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 311, 21, 7}}) ->
    io:format("\tMicrosoft szOID_CERTIFICATE_TEMPLATE~n");
print_extension(#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 311, 21, 10}}) ->
    io:format("\tMicrosoft szOID_APPLICATION_CERT_POLICIES~n");
print_extension(#'Extension'{extnID = ?'id-pe-authorityInfoAccess', extnValue = ExtnValue}) ->
    io:format("\tAuthority Info Access:~n", []),
    print_authority_info_access(ExtnValue);
print_extension(#'Extension'{extnID = {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, extnValue = _ExtnValue}) ->
    io:format("\tSignedCertificateTimestampList.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-basicConstraints', extnValue = ExtnValue}) ->
    io:format("\tBasic constraints: "),
    io:format("CA=~p. ", [ExtnValue#'BasicConstraints'.cA]),
    case ExtnValue#'BasicConstraints'.pathLenConstraint of
        asn1_NOVALUE -> io:format("No path length constraint.~n");
        Val -> io:format("Path length constraint: ~tp~n", [Val])
    end;
print_extension(#'Extension'{extnID = ?'id-ce-certificatePolicies', extnValue = ExtnValue}) ->
    io:format("\tCertificate policies:~n", []),
    print_certificate_policies(ExtnValue);
print_extension(#'Extension'{extnID = ?'id-ce-cRLDistributionPoints', extnValue = ExtnValue}) ->
    io:format("\tCRL distribution points:~n", []),
    print_crl_distribution(ExtnValue);
print_extension(#'Extension'{extnID = ?'id-ce-extKeyUsage', extnValue = ExtnValue}) ->
    io:format("\tExtended key usage: ~ts~n", [lists:join(", ", [oid2str(E) || E <- ExtnValue])]);
print_extension(#'Extension'{extnID = ?'id-ce-keyUsage', extnValue = ExtnValue}) ->
    io:format("\tKey Usage: ~ts~n", [lists:join(", ", [erlang:atom_to_list(E) || E <- ExtnValue])]);
print_extension(#'Extension'{extnID = ?'id-ce-authorityKeyIdentifier', extnValue = _ExtnValue}) ->
    io:format("\tAuthority Key Identifier.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-subjectKeyIdentifier'}) ->
    io:format("\tSubject Key Identifier.~n", []);
print_extension(#'Extension'{extnID = ?'id-ce-subjectAltName'}) ->
    io:format("\tSubject alternative names (see above for list).~n", []);
print_extension(E) ->
    io:format("\t~tp~n", [E#'Extension'.extnID]).

oid2str(?'id-kp-serverAuth') -> "id-kp-serverAuth";
oid2str(?'id-kp-clientAuth') -> "id-kp-clientAuth";
oid2str({1, 3, 6, 1, 5, 5, 7, 48, 1}) -> "OCSP";
oid2str({1, 3, 6, 1, 5, 5, 7, 48, 2}) -> "caIssuers";
oid2str({2, 23, 140, 1, 2, 1}) -> "domain-validated";
oid2str({1, 3, 6, 1, 4, 1, 44947, 1, 1, 1}) -> "ISRG Domain Validated";
oid2str({2, 23, 140, 1, 1}) -> "EV Guidelines";
oid2str({2, 16, 840, 1, 114412, 2, 1}) -> "DigiCert EV TLS";
oid2str({2, 23, 140, 1, 2, 2}) -> "Organization validated";
oid2str(OID) -> lists:join(".", lists:map(fun erlang:integer_to_list/1, erlang:tuple_to_list(OID))).

print_crl_distribution(Data) ->
    List = public_key:der_decode('CRLDistributionPoints', Data),
    lists:foreach(
        fun(L) ->
            {fullName, [{uniformResourceIdentifier, URL}]} =
                L#'DistributionPoint'.distributionPoint,
            io:format("\t\t~ts~n", [URL])
        end,
        List
    ).

print_authority_info_access(ExtnValue) ->
    lists:foreach(
        fun(E) ->
            Method = oid2str(E#'AccessDescription'.accessMethod),
            {uniformResourceIdentifier, URL} = E#'AccessDescription'.accessLocation,
            io:format("\t\t~ts ~ts~n", [Method, URL])
        end,
        ExtnValue
    ).

print_certificate_policies(ExtnValue) ->
    lists:foreach(
        fun(E) ->
            io:format("\t\t~ts~n", [oid2str(E#'PolicyInformation'.policyIdentifier)])
        end,
        ExtnValue
    ).

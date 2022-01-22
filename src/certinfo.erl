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
    {utcTime, NotBefore} = Validity#'Validity'.notBefore,
    {utcTime, NotAfter} = Validity#'Validity'.notAfter,
    io:format("Not valid before: ~s~n", [NotBefore]),
    io:format("Not valid after: ~s~n", [NotAfter]),
    SAN = lists:keyfind({2, 5, 29, 17}, 2, Extensions),
    Names = lists:map(fun({dNSName, Name}) -> Name end, SAN#'Extension'.extnValue),
    io:format("DNSNames: ~tp~n", [Names]),
    erlang:halt(0).

%%====================================================================
%% Internal functions
%%====================================================================

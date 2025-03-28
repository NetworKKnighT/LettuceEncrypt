// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class ServerStartupState : SyncAcmeState
{
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly CertificateSelector _selector;
    private readonly DomainNamesEnumerator _domainNamesEnumerator;
    private readonly ILogger<ServerStartupState> _logger;

    public ServerStartupState(
        AcmeStateMachineContext context,
        IOptions<LettuceEncryptOptions> options,
        CertificateSelector selector,
        DomainNamesEnumerator domainNamesEnumerator,
        ILogger<ServerStartupState> logger) :
        base(context)
    {
        _options = options;
        _selector = selector;
        _domainNamesEnumerator = domainNamesEnumerator;
        _logger = logger;
    }

    public override IAcmeState MoveNext()
    {
        while (_domainNamesEnumerator.MoveNext())
        {
            var domainNames = _domainNamesEnumerator.Current;
            var hasCertForAllDomains = domainNames.All(_selector.HasCertForDomain);
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for [{domainNames}] already found.", string.Join(", ", domainNames));
                return MoveTo<CheckForRenewalState>();
            }

            return MoveTo<BeginCertificateCreationState>();
        }

        _domainNamesEnumerator.Reset();
        return MoveTo<WaitState>();
    }
}

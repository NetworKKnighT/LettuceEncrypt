// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class WaitState : AcmeState
{
    private readonly ILogger<WaitState> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly CertificateSelector _selector;
    private readonly IClock _clock;

    public WaitState(
        AcmeStateMachineContext context,
        ILogger<WaitState> logger,
        IOptions<LettuceEncryptOptions> options,
        CertificateSelector selector,
        IClock clock) : base(context)
    {
        _logger = logger;
        _options = options;
        _selector = selector;
        _clock = clock;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        var checkPeriod = _options.Value.RenewalCheckPeriod;
        if (!checkPeriod.HasValue)
        {
            _logger.LogInformation("Automatic certificate renewal is not configured. Stopping {service}",
                                   nameof(AcmeCertificateLoader));
            return MoveTo<TerminalState>();
        }

        await Task.Delay(checkPeriod.Value, cancellationToken);

        return MoveTo<ServerStartupState>();
    }
}

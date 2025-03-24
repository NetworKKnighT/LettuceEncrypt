// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class DomainNamesEnumerator : IEnumerator
{
    private readonly string[][] _domains;

    private int _position = -1;

    public DomainNamesEnumerator(IOptions<LettuceEncryptOptions> options)
    {
        _domains = options.Value.DomainNames;
    }

    public bool MoveNext()
    {
        _position++;
        return _position < _domains.Length;
    }

    public void Reset()
    {
        _position = -1;
    }

    object IEnumerator.Current
    {
        get
        {
            return Current;
        }
    }

    public string[] Current
    {
        get
        {
            try
            {
                return _domains[_position];
            }
            catch (IndexOutOfRangeException)
            {
                throw new InvalidOperationException();
            }
        }
    }
}

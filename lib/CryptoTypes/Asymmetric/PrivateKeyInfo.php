<?php

declare(strict_types = 1);

namespace Sop\CryptoTypes\Asymmetric;

/**
 * PrivateKeyInfo was first introduced in RFC 5208, but later
 * refined as OneAsymmetricKey in RFC 5958 with backwards compatibility.
 *
 * Thus `PrivateKeyInfo ::= OneAsymmetricKey`
 *
 * @see https://tools.ietf.org/html/rfc5208#section-5
 * @see https://tools.ietf.org/html/rfc5958#section-2
 */
class PrivateKeyInfo extends OneAsymmetricKey
{
}

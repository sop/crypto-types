<?php

namespace Sop\CryptoTypes\AlgorithmIdentifier\Signature;

use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;

/**
 * Base class for signature algorithms employing RSASSA.
 */
abstract class RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements 
    SignatureAlgorithmIdentifier
{
    /**
     *
     * {@inheritdoc}
     *
     */
    public function supportsKeyAlgorithm(AlgorithmIdentifier $algo)
    {
        return $algo->oid() == self::OID_RSA_ENCRYPTION;
    }
}

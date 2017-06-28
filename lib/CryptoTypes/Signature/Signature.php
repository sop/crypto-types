<?php

namespace Sop\CryptoTypes\Signature;

use ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECSignatureAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\RSASignatureAlgorithmIdentifier;

/**
 * Base class for signature values.
 */
abstract class Signature
{
    /**
     * Get the signature as a BitString.
     *
     * @return \ASN1\Type\Primitive\BitString
     */
    abstract public function bitString();
    
    /**
     * Get signature object by signature data and used algorithm.
     *
     * @param string $data Signature value
     * @param AlgorithmIdentifier $algo
     * @return self
     */
    public static function fromSignatureData($data, AlgorithmIdentifier $algo)
    {
        if ($algo instanceof RSASignatureAlgorithmIdentifier) {
            return RSASignature::fromSignatureString($data);
        }
        if ($algo instanceof ECSignatureAlgorithmIdentifier) {
            return ECSignature::fromDER($data);
        }
        return new GenericSignature(new BitString($data), $algo);
    }
}

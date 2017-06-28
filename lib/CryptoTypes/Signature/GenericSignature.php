<?php

namespace Sop\CryptoTypes\Signature;

use ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;

/**
 * Generic signature value container.
 */
class GenericSignature extends Signature
{
    /**
     * Signature value.
     *
     * @var BitString
     */
    private $_signature;
    
    /**
     * Signature algorithm.
     *
     * @var AlgorithmIdentifier
     */
    private $_signatureAlgorithm;
    
    /**
     * Constructor.
     *
     * @param BitString $signature
     * @param AlgorithmIdentifier $algo
     */
    public function __construct(BitString $signature, AlgorithmIdentifier $algo)
    {
        $this->_signature = $signature;
        $this->_signatureAlgorithm = $algo;
    }
    
    /**
     * Get the signature algorithm.
     *
     * @return AlgorithmIdentifier
     */
    public function signatureAlgorithm()
    {
        return $this->_signatureAlgorithm;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function bitString()
    {
        return $this->_signature;
    }
}

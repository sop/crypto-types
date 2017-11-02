<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier\Feature;

/**
 * Base interface for algorithm identifiers.
 */
interface AlgorithmIdentifierType
{
    /**
     * Get the object identifier of the algorithm.
     *
     * @return string Object identifier in dotted format
     */
    public function oid();
    
    /**
     * Get a human readable name of the algorithm.
     *
     * @return string
     */
    public function name(): string;
    
    /**
     * Generate ASN.1 structure.
     *
     * @return \ASN1\Type\Constructed\Sequence
     */
    public function toASN1();
}

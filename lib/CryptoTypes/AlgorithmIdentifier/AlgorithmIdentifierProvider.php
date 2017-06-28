<?php

namespace Sop\CryptoTypes\AlgorithmIdentifier;

/**
 * Interface to provide lookup from OID to class name of specific algorithm
 * identifier type implementations.
 *
 * This allows AlgorithmIdentifier types to be implemented in external
 * libraries and to use AlgorithmIdentifierFactory to resolve them.
 */
interface AlgorithmIdentifierProvider
{
    /**
     * Check whether this provider supports algorithm identifier of given OID.
     *
     * @param string $oid Object identifier in dotted format
     * @return bool
     */
    public function supportsOID($oid);
    
    /**
     * Get the name of a class that implements algorithm identifier for given
     * OID.
     *
     * @param string $oid Object identifier in dotted format
     * @throws \UnexpectedValueException If OID is not supported
     * @return string Fully qualified name of a class that extends
     *         SpecificAlgorithmIdentifier
     */
    public function getClassByOID($oid);
}

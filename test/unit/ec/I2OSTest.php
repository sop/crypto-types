<?php
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;

/**
 * @group conversion
 */
class IntegerToOctetStringConversionTest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testOSType()
    {
        $os = ECConversion::integerToOctetString(new Integer(42));
        $this->assertInstanceOf(OctetString::class, $os);
    }
    
    /**
     */
    public function testIntegerType()
    {
        $num = ECConversion::octetStringToInteger(new OctetString("\x42"));
        $this->assertInstanceOf(Integer::class, $num);
    }
    
    /**
     */
    public function testLength()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 2);
        $this->assertEquals(2, strlen($os->string()));
    }
    
    /**
     */
    public function testPad()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 3);
        $this->assertEquals(3, strlen($os->string()));
    }
    
    /**
     * @expectedException RangeException
     */
    public function testTooLarge()
    {
        ECConversion::integerToOctetString(new Integer(256), 1);
    }
    
    /**
     * @dataProvider provideConvert
     */
    public function testConvert(Integer $num, $mlen, OctetString $os)
    {
        $tmp = ECConversion::integerToOctetString($num, $mlen);
        $this->assertEquals($os, $tmp);
        $result = ECConversion::octetStringToInteger($tmp);
        $this->assertEquals($num, $result);
    }
    
    /**
     *
     * @return array
     */
    public function provideConvert()
    {
        return array(
            /* @formatter:off */
            [new Integer(0), 1, new OctetString("\0")],
            [new Integer(0), 2, new OctetString("\0\0")],
            [new Integer(1), 1, new OctetString("\1")],
            [new Integer(1), 2, new OctetString("\0\1")],
            [new Integer(1), 8, new OctetString("\0\0\0\0\0\0\0\1")],
            [new Integer("4294967295"), 4, new OctetString("\xff\xff\xff\xff")],
            /* @formatter:on */
        );
    }
    
    /**
     */
    public function testNumberToOctets()
    {
        $octets = ECConversion::numberToOctets(0x42);
        $this->assertEquals("\x42", $octets);
    }
    
    /**
     */
    public function testOctetsToNumber()
    {
        $number = ECConversion::octetsToNumber("\x42");
        $this->assertEquals(0x42, $number);
    }
}

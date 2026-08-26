<?php

/**
 * RCFourTest.php
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Test;

/**
 * RC4 encryption Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class RCFourTest extends TestUtil
{
    protected function getTestObject(): \Com\Tecnick\Pdf\Encrypt\Type\RCFour
    {
        return new \Com\Tecnick\Pdf\Encrypt\Type\RCFour();
    }

    /** RCFourFive produces the same output as RCFour. */
    public function testEncrypt40(): void
    {
        $rcFour = $this->getTestObject();
        $data = 'alpha';
        $key = '12345'; // 5 bytes = 40 bit KEY

        $rcFourFive = new \Com\Tecnick\Pdf\Encrypt\Type\RCFourFive();
        $this->assertSame($rcFour->encrypt($data, $key), $rcFourFive->encrypt($data, $key));
    }

    /** RCFourSixteen produces the same output as RCFour. */
    public function testEncrypt128(): void
    {
        $rcFour = $this->getTestObject();
        $data = 'alpha';
        $key = '0123456789abcdef'; // 16 bytes = 128 bit KEY

        $rcFourSixteen = new \Com\Tecnick\Pdf\Encrypt\Type\RCFourSixteen();
        $this->assertSame($rcFour->encrypt($data, $key), $rcFourSixteen->encrypt($data, $key));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rc4ModeProvider(): array
    {
        return [
            'default' => [''],
            'RC4' => ['RC4'],
            'RC4-40' => ['RC4-40'],
        ];
    }

    /** The mode name does not change the keystream: only the key bytes do. */
    #[\PHPUnit\Framework\Attributes\DataProvider('rc4ModeProvider')]
    public function testTheModeNameDoesNotChangeTheKeystream(string $mode): void
    {
        $key = \hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertIsString($key);
        $keystream = $this->getTestObject()->encrypt(\str_repeat("\x00", 16), $key, $mode);
        $this->assertSame('9ac7cc9a609d1ef7b2932899cde41b97', \bin2hex($keystream));
    }

    public function testEncryptException(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $rcFour = $this->getTestObject();
        $rcFour->encrypt('alpha', '12345', 'ERROR');
    }

    /** An empty key raises the library exception. */
    public function testEncryptEmptyKeyThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->encrypt('alpha', '');
    }

    /**
     * The first 16 keystream bytes of each key, from RFC 6229 section 2. The
     * plaintext is all zero, so the ciphertext is the keystream itself.
     *
     * @return array<string, array{string, string}>
     */
    public static function rc4VectorProvider(): array
    {
        return [
            '40 bit' => ['0102030405', 'b2396305f03dc027ccc3524a0a1118a8'],
            '64 bit' => ['0102030405060708', '97ab8a1bf0afb96132f2f67258da15a8'],
            '128 bit' => ['0102030405060708090a0b0c0d0e0f10', '9ac7cc9a609d1ef7b2932899cde41b97'],
            '256 bit' => [
                '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
                'eaa6bd25880bf93d3f5d1e4ca2611d91',
            ],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('rc4VectorProvider')]
    public function testRc4KnownAnswer(string $hexKey, string $expectedKeystream): void
    {
        $key = \hex2bin($hexKey);
        $this->assertIsString($key);
        $keystream = $this->getTestObject()->encrypt(\str_repeat("\x00", 16), $key);
        $this->assertSame($expectedKeystream, \bin2hex($keystream));
    }

    /** RC4 is symmetric: encrypting twice returns the plaintext. */
    public function testRc4IsSymmetric(): void
    {
        $rcFour = $this->getTestObject();
        $plaintext = 'the quick brown fox';
        $key = '0123456789abcdef';
        $this->assertSame($plaintext, $rcFour->encrypt($rcFour->encrypt($plaintext, $key), $key));
    }
}

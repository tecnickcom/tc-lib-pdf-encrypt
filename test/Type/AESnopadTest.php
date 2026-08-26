<?php

/**
 * AESnopadTest.php
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

use Com\Tecnick\Pdf\Encrypt\Type\AESnopad;

/**
 * AESnopad encryption Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class AESnopadTest extends TestUtil
{
    /**
     * 32-byte key for the aes-256-cbc variant.
     */
    private const KEY256 = '0123456789abcdef0123456789abcdef';

    /**
     * 16-byte key for the aes-128-cbc variant.
     */
    private const KEY128 = '0123456789abcdef';

    protected function getTestObject(): AESnopad
    {
        return new AESnopad();
    }

    /**
     * Length of the ciphertext of a plaintext of $plainLen bytes: the input
     * length rounded up to a multiple of BLOCKSIZE, with no IV prefix.
     */
    private function expectedCiphertextLen(int $plainLen): int
    {
        $rem = $plainLen % AESnopad::BLOCKSIZE;
        return $rem === 0 ? $plainLen : $plainLen + (AESnopad::BLOCKSIZE - $rem);
    }

    // --- output length ---

    public function testEncryptOutputLenShortData(): void
    {
        // 5 bytes → padded to 16
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 5), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(5), \strlen($enc));
    }

    public function testEncryptOutputLenExactlyOneBlock(): void
    {
        // 16 bytes → already aligned, no padding → 16
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 16), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(16), \strlen($enc));
    }

    public function testEncryptOutputLenJustOverOneBlock(): void
    {
        // 17 bytes → padded to 32
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 17), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(17), \strlen($enc));
    }

    public function testEncryptOutputLenTwoBlocks(): void
    {
        // 32 bytes → already aligned, no padding → 32
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 32), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(32), \strlen($enc));
    }

    public function testEncryptOutputLenJustOverTwoBlocks(): void
    {
        // 33 bytes → padded to 48
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 33), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(33), \strlen($enc));
    }

    public function testEncryptOutputLenLargeData(): void
    {
        // 100 bytes → padded to 112
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 100), self::KEY256);
        $this->assertSame($this->expectedCiphertextLen(100), \strlen($enc));
    }

    /** A longer input produces a longer ciphertext. */
    public function testCiphertextGrowsWithPlaintext(): void
    {
        $aesnopad = $this->getTestObject();
        $key = self::KEY256;

        $short = $aesnopad->encrypt(\str_repeat('a', 5), $key);
        $long = $aesnopad->encrypt(\str_repeat('a', 100), $key);

        $this->assertGreaterThan(\strlen($short), \strlen($long));
    }

    // --- aes-128-cbc variant ---

    public function testEncryptAes128OutputLen(): void
    {
        // 17 bytes → padded to 32
        $enc = $this->getTestObject()->encrypt(\str_repeat('x', 17), self::KEY128, AESnopad::IVECT, 'aes-128-cbc');
        $this->assertSame($this->expectedCiphertextLen(17), \strlen($enc));
    }

    /** A key that does not match the cipher is rejected. */
    public function testEncryptWrongKeyLengthThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->encrypt('data', self::KEY128, AESnopad::IVECT, 'aes-256-cbc');
    }

    public function testDecryptWrongKeyLengthThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->decrypt(\str_repeat('c', 32), self::KEY256, AESnopad::IVECT, 'aes-128-cbc');
    }

    /** NIST SP 800-38A F.2.5 AES-256-CBC vector, first block only. */
    public function testAes256CbcKnownAnswer(): void
    {
        $key = \hex2bin('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
        $ivect = \hex2bin('000102030405060708090a0b0c0d0e0f');
        $plaintext = \hex2bin('6bc1bee22e409f96e93d7e117393172a');
        $this->assertIsString($key);
        $this->assertIsString($ivect);
        $this->assertIsString($plaintext);

        $enc = $this->getTestObject()->encrypt($plaintext, $key, $ivect);
        $this->assertSame('f58c4c04d6e5f1ba779eabfb5f7bfbd6', \bin2hex($enc));
        $this->assertSame($plaintext, $this->getTestObject()->decrypt($enc, $key, $ivect));
    }

    // --- deterministic output with fixed IV ---

    public function testEncryptDeterministicWithFixedIv(): void
    {
        $aesnopad = $this->getTestObject();
        $data = \str_repeat('x', 32);
        $key = self::KEY256;

        $enc1 = $aesnopad->encrypt($data, $key, AESnopad::IVECT, 'aes-256-cbc');
        $enc2 = $aesnopad->encrypt($data, $key, AESnopad::IVECT, 'aes-256-cbc');
        $this->assertSame($enc1, $enc2);
    }

    // --- exception paths ---

    public function testCheckCipherInvalidName(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->checkCipher('des-cbc');
    }

    public function testEncryptInvalidCipher(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->encrypt('data', self::KEY256, AESnopad::IVECT, 'des-cbc');
    }

    /** Every cipher in VALID_CIPHERS is provided by the runtime. */
    public function testEveryValidCipherIsAvailable(): void
    {
        $available = \openssl_get_cipher_methods();
        foreach (AESnopad::VALID_CIPHERS as $cipher) {
            $this->assertContains($cipher, $available, $cipher);
        }
    }

    public function testDecryptInvalidCiphertextLength(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->decrypt('short', self::KEY256, AESnopad::IVECT, 'aes-256-cbc');
    }
}

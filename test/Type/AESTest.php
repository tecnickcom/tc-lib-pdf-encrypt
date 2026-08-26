<?php

/**
 * AESTest.php
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
 * AES encryption Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class AESTest extends TestUtil
{
    protected function getTestObject(): \Com\Tecnick\Pdf\Encrypt\Type\AES
    {
        return new \Com\Tecnick\Pdf\Encrypt\Type\AES();
    }

    /**
     * Split the 16-byte IV prefix off and decrypt the remainder with OpenSSL,
     * which validates the PKCS#7 padding as well.
     */
    private function decryptWithOpenSsl(string $encrypted, string $key, string $cipher): string
    {
        $plain = \openssl_decrypt(\substr($encrypted, 16), $cipher, $key, OPENSSL_RAW_DATA, \substr($encrypted, 0, 16));
        $this->assertIsString($plain);
        return $plain;
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function cipherProvider(): array
    {
        return [
            'aes-128-cbc' => ['aes-128-cbc', '0123456789abcdef'],
            'aes-256-cbc' => ['aes-256-cbc', '0123456789abcdef0123456789abcdef'],
        ];
    }

    /** The ciphertext decrypts back to the plaintext. */
    #[\PHPUnit\Framework\Attributes\DataProvider('cipherProvider')]
    public function testEncryptedPayloadDecryptsToThePlaintext(string $cipher, string $key): void
    {
        $aes = $this->getTestObject();

        foreach (['', 'alpha', \str_repeat('x', 16), \str_repeat('x', 100)] as $plaintext) {
            $encrypted = $aes->encrypt($plaintext, $key, $cipher);
            $this->assertSame($plaintext, $this->decryptWithOpenSsl($encrypted, $key, $cipher), $cipher);
        }
    }

    /** The IV prefix is the one the ciphertext was produced with. */
    #[\PHPUnit\Framework\Attributes\DataProvider('cipherProvider')]
    public function testTheIvPrefixIsTheOneUsed(string $cipher, string $key): void
    {
        // Three blocks: replacing the IV corrupts the first one and leaves the
        // padding of the last one valid, so the decryption completes.
        $plaintext = \str_repeat('x', 40);
        $encrypted = $this->getTestObject()->encrypt($plaintext, $key, $cipher);
        $wrongIv = \str_repeat("\x00", 16) . \substr($encrypted, 16);

        $this->assertSame($plaintext, $this->decryptWithOpenSsl($encrypted, $key, $cipher));
        $this->assertNotSame($plaintext, $this->decryptWithOpenSsl($wrongIv, $key, $cipher));
    }

    /** Arbitrary bytes survive the round trip unchanged. */
    public function testBinaryPayloadDecryptsToThePlaintext(): void
    {
        $key = '0123456789abcdef0123456789abcdef';
        $plaintext = \random_bytes(257);
        $encrypted = $this->getTestObject()->encrypt($plaintext, $key, 'aes-256-cbc');
        $this->assertSame(\bin2hex($plaintext), \bin2hex($this->decryptWithOpenSsl($encrypted, $key, 'aes-256-cbc')));
    }

    /** The default cipher for a 16-byte key is AES-128. */
    public function testDefaultCipherFollowsTheKeyLength(): void
    {
        $aes = $this->getTestObject();

        $enc128 = $aes->encrypt('alpha', '0123456789abcdef');
        $this->assertSame('alpha', $this->decryptWithOpenSsl($enc128, '0123456789abcdef', 'aes-128-cbc'));

        $key256 = '0123456789abcdef0123456789abcdef';
        $enc256 = $aes->encrypt('alpha', $key256, '');
        $this->assertSame('alpha', $this->decryptWithOpenSsl($enc256, $key256, 'aes-256-cbc'));
    }

    public function testEncrypt128(): void
    {
        $aes = $this->getTestObject();
        $data = 'alpha';
        $key = '0123456789abcdef'; // 16 bytes = 128 bit KEY

        $enc_a = $aes->encrypt($data, $key);
        $enc_b = $aes->encrypt($data, $key, 'aes-128-cbc');
        $this->assertEquals(\strlen($enc_a), \strlen($enc_b));

        $aesSixteen = new \Com\Tecnick\Pdf\Encrypt\Type\AESSixteen();
        $enc_c = $aesSixteen->encrypt($data, $key);
        $this->assertEquals(\strlen($enc_a), \strlen($enc_c));
    }

    public function testEncrypt256(): void
    {
        $aes = $this->getTestObject();
        $data = 'alpha';
        $key = '0123456789abcdef0123456789abcdef'; // 32 bytes = 256 bit KEY

        $enc_a = $aes->encrypt($data, $key, '');
        $enc_b = $aes->encrypt($data, $key, 'aes-256-cbc');
        $this->assertEquals(\strlen($enc_a), \strlen($enc_b));

        $aesThirtytwo = new \Com\Tecnick\Pdf\Encrypt\Type\AESThirtytwo();
        $enc_c = $aesThirtytwo->encrypt($data, $key);
        $this->assertEquals(\strlen($enc_a), \strlen($enc_c));
    }

    /**
     * The output is a 16-byte IV followed by the PKCS#7-padded ciphertext, so an
     * aligned input carries one full padding block.
     */
    public function testEncrypt128LongData(): void
    {
        $aes = $this->getTestObject();
        $key = '0123456789abcdef'; // 16 bytes = 128 bit KEY

        // 17 bytes → padded to 32 → 32 ciphertext + 16 IV = 48
        $enc17 = $aes->encrypt(\str_repeat('x', 17), $key, 'aes-128-cbc');
        $this->assertSame(48, \strlen($enc17));

        // 32 bytes → padded to 48 (full PKCS#7 block) → 48 + 16 = 64
        $enc32 = $aes->encrypt(\str_repeat('x', 32), $key, 'aes-128-cbc');
        $this->assertSame(64, \strlen($enc32));

        // 33 bytes → padded to 48 → 48 + 16 = 64
        $enc33 = $aes->encrypt(\str_repeat('x', 33), $key, 'aes-128-cbc');
        $this->assertSame(64, \strlen($enc33));

        // A shorter input produces a shorter output.
        $encShort = $aes->encrypt('alpha', $key, 'aes-128-cbc'); // 5 bytes → 32
        $this->assertGreaterThan(\strlen($encShort), \strlen($enc33));
    }

    public function testEncrypt256LongData(): void
    {
        $aes = $this->getTestObject();
        $key = '0123456789abcdef0123456789abcdef'; // 32 bytes = 256 bit KEY

        // 17 bytes → padded to 32 → 32 ciphertext + 16 IV = 48
        $enc17 = $aes->encrypt(\str_repeat('x', 17), $key, 'aes-256-cbc');
        $this->assertSame(48, \strlen($enc17));

        // 32 bytes → padded to 48 (full PKCS#7 block) → 48 + 16 = 64
        $enc32 = $aes->encrypt(\str_repeat('x', 32), $key, 'aes-256-cbc');
        $this->assertSame(64, \strlen($enc32));

        // 100 bytes → padded to 112 → 112 + 16 = 128
        $enc100 = $aes->encrypt(\str_repeat('x', 100), $key, 'aes-256-cbc');
        $this->assertSame(128, \strlen($enc100));

        $aesThirtytwo = new \Com\Tecnick\Pdf\Encrypt\Type\AESThirtytwo();
        $enc100b = $aesThirtytwo->encrypt(\str_repeat('x', 100), $key);
        $this->assertSame(\strlen($enc100), \strlen($enc100b));
    }

    public function testEncryptException(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $aes = $this->getTestObject();
        $aes->encrypt('alpha', '12345', 'ERROR');
    }

    /** A key that does not match the cipher is rejected. */
    public function testEncryptWrongKeyLengthThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->getTestObject()->encrypt('alpha', '12345', 'aes-128-cbc');
    }

    /** Each call uses a fresh random IV. */
    public function testEncryptUsesFreshIv(): void
    {
        $aes = $this->getTestObject();
        $key = '0123456789abcdef';
        $enc1 = $aes->encrypt('alpha', $key, 'aes-128-cbc');
        $enc2 = $aes->encrypt('alpha', $key, 'aes-128-cbc');
        $this->assertNotSame(\substr($enc1, 0, 16), \substr($enc2, 0, 16));
        $this->assertNotSame($enc1, $enc2);
    }
}

<?php

/**
 * SeedTest.php
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
 * Seed Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class SeedTest extends TestUtil
{
    protected function getTestObject(): \Com\Tecnick\Pdf\Encrypt\Type\Seed
    {
        return new \Com\Tecnick\Pdf\Encrypt\Type\Seed();
    }

    /** The output is SEEDLEN random bytes followed by the two arguments, in order. */
    public function testEncrypt(): void
    {
        $seed = $this->getTestObject();
        $result = $seed->encrypt('hello', 'world');

        $this->assertSame(\Com\Tecnick\Pdf\Encrypt\Type\Seed::SEEDLEN + 10, \strlen($result));
        $this->assertSame('helloworld', \substr($result, \Com\Tecnick\Pdf\Encrypt\Type\Seed::SEEDLEN));
    }

    /** Both arguments are optional and default to nothing. */
    public function testEncryptWithoutArguments(): void
    {
        $result = $this->getTestObject()->encrypt();
        $this->assertSame(\Com\Tecnick\Pdf\Encrypt\Type\Seed::SEEDLEN, \strlen($result));
    }

    /** The random part differs on every call and spans many distinct bytes. */
    public function testEncryptIsRandom(): void
    {
        $seed = $this->getTestObject();
        $seedlen = \Com\Tecnick\Pdf\Encrypt\Type\Seed::SEEDLEN;

        $first = \substr($seed->encrypt('hello', 'world'), 0, $seedlen);
        $second = \substr($seed->encrypt('hello', 'world'), 0, $seedlen);

        $this->assertNotSame(\bin2hex($first), \bin2hex($second));
        $this->assertNotSame(\str_repeat('00', \max(0, $seedlen)), \bin2hex($first));
        $this->assertGreaterThan(32, \count(\array_unique(\str_split($first))));
    }

    /** The third argument is unused and does not reach the output. */
    public function testEncryptIgnoresTheModeArgument(): void
    {
        $seed = $this->getTestObject();
        $seedlen = \Com\Tecnick\Pdf\Encrypt\Type\Seed::SEEDLEN;

        $result = $seed->encrypt('hello', 'world', 'raw');
        $this->assertSame($seedlen + 10, \strlen($result));
        $this->assertSame('helloworld', \substr($result, $seedlen));
    }
}

<?php

/**
 * DeterministicEncrypt.php
 *
 * @since     2026-08-26
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
 * An Encrypt whose random source is replaced by a counter.
 *
 * Every random value in Compute goes through randomSeed(), so overriding it pins
 * the file key, the R5/R6 salts and the trailing Perms bytes.
 *
 * @since     2026-08-26
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class DeterministicEncrypt extends \Com\Tecnick\Pdf\Encrypt\Encrypt
{
    /**
     * Number of seeds handed out so far.
     */
    private int $counter = 0;

    /**
     * Return a reproducible seed that differs on every call.
     *
     * SHA-512 yields Seed::SEEDLEN bytes.
     */
    protected function randomSeed(): string
    {
        ++$this->counter;
        return \hash('sha512', 'tc-lib-pdf-encrypt fixed seed ' . $this->counter, true);
    }
}

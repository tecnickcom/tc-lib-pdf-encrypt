<?php

declare(strict_types=1);

/**
 * Algorithm2BProbe.php
 *
 * @since     2026-08-27
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
 * An Encrypt that exposes the Algorithm 2.B hash, so that a known-answer vector
 * can use a chosen salt.
 *
 * @since     2026-08-27
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class Algorithm2BProbe extends \Com\Tecnick\Pdf\Encrypt\Encrypt
{
    /**
     * Compute the Algorithm 2.B hash of a chosen password, salt and user hash.
     *
     * @throws \Com\Tecnick\Pdf\Encrypt\Exception
     */
    public function hashOf(#[\SensitiveParameter] string $password, string $salt, string $userHash = ''): string
    {
        return $this->hash2B($password, $salt, $userHash);
    }
}

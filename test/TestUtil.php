<?php

/**
 * TestUtil.php
 *
 * @since     2020-12-19
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2015-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Test;

use PHPUnit\Framework\TestCase;

/**
 * Test Util
 *
 * @since     2020-12-19
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2015-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class TestUtil extends TestCase
{
    /**
     * Expect an exception, optionally with a message that contains $message.
     *
     * @param class-string<\Throwable> $exception
     * @param string                   $message   Substring the message must contain; '' accepts any message.
     */
    public function bcExpectException(string $exception, string $message = ''): void
    {
        parent::expectException($exception);

        if ($message !== '') {
            // expectExceptionMessageMatches() is available across the whole
            // supported PHPUnit range.
            parent::expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        }
    }

    /**
     * Execute a callback and assert that it triggers a matching user deprecation.
     *
     * @param callable():void $callback
     */
    public function bcAssertUserDeprecationMessageMatches(string $pattern, callable $callback): void
    {
        $messages = [];

        \set_error_handler(static function (int $errno, string $errstr) use (&$messages): bool {
            if ($errno !== E_USER_DEPRECATED) {
                return false;
            }

            $messages[] = $errstr;
            return true;
        });

        try {
            $callback();
        } finally {
            \restore_error_handler();
        }

        $this->assertNotEmpty($messages, 'Expected a user deprecation but none was triggered.');

        foreach ($messages as $message) {
            if (\preg_match($pattern, $message) === 1) {
                return;
            }
        }

        $this->fail(
            'User deprecation message did not match pattern ' . $pattern . '. Got: ' . \implode(' | ', $messages),
        );
    }

    /**
     * Execute a callback while swallowing user deprecations.
     *
     * @template T
     * @param callable():T $callback
     * @return T
     */
    public function bcRunIgnoringUserDeprecations(callable $callback): mixed
    {
        \set_error_handler(static fn(int $errno): bool => $errno === E_USER_DEPRECATED);

        try {
            return $callback();
        } finally {
            \restore_error_handler();
        }
    }

    /**
     * Execute a callback and assert that it triggers a matching user warning.
     *
     * @param callable():void $callback
     */
    public function bcAssertUserWarningMessageMatches(string $pattern, callable $callback): void
    {
        $messages = [];

        \set_error_handler(static function (int $errno, string $errstr) use (&$messages): bool {
            if ($errno !== E_USER_WARNING && $errno !== E_USER_DEPRECATED) {
                return false;
            }

            if ($errno === E_USER_WARNING) {
                $messages[] = $errstr;
            }

            return true;
        });

        try {
            $callback();
        } finally {
            \restore_error_handler();
        }

        $this->assertNotEmpty($messages, 'Expected a user warning but none was triggered.');

        foreach ($messages as $message) {
            if (\preg_match($pattern, $message) === 1) {
                return;
            }
        }

        $this->fail('User warning message did not match pattern ' . $pattern . '. Got: ' . \implode(' | ', $messages));
    }

    /**
     * Execute a callback while swallowing user deprecations and warnings.
     *
     * @template T
     * @param callable():T $callback
     * @return T
     */
    public function bcRunIgnoringUserNotices(callable $callback): mixed
    {
        \set_error_handler(static fn(int $errno): bool => $errno === E_USER_DEPRECATED || $errno === E_USER_WARNING);

        try {
            return $callback();
        } finally {
            \restore_error_handler();
        }
    }
}

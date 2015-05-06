<?php
/**
 * AsciiHex.php
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfFilter
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-filter
 *
 * This file is part of tc-lib-pdf-filter software library.
 */

namespace Com\Tecnick\Pdf\Filter\Type;

use \Com\Tecnick\Pdf\Filter\Exception as PPException;

/**
 * Com\Tecnick\Pdf\Filter\Type\AsciiHex
 *
 * ASCIIHex
 * Decodes data encoded in an ASCII hexadecimal representation, reproducing the original binary data.
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfFilter
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-filter
 */
class AsciiHex
{
    /**
     * Decode the data
     *
     * @param string $data Data to decode.
     *
     * @return string Decoded data string.
     */
    public function decode($data)
    {
        // initialize string to return
        $decoded = '';
        // all white-space characters shall be ignored
        $data = preg_replace('/[\s]/', '', $data);
        // check for EOD character: GREATER-THAN SIGN (3Eh)
        $eod = strpos($data, '>');
        if ($eod !== false) {
            // remove EOD and extra data (if any)
            $data = substr($data, 0, $eod);
            $eod = true;
        }
        // get data length
        $data_length = strlen($data);
        if (($data_length % 2) != 0) {
            // odd number of hexadecimal digits
            if ($eod) {
                // EOD shall behave as if a 0 (zero) followed the last digit
                $data = substr($data, 0, -1).'0'.substr($data, -1);
            } else {
                throw new PPException('invalid code');
            }
        }
        // check for invalid characters
        if (preg_match('/[^a-fA-F\d]/', $data) > 0) {
            throw new PPException('invalid code');
        }
        // get one byte of binary data for each pair of ASCII hexadecimal digits
        $decoded = pack('H*', $data);
        return $decoded;
    }
}

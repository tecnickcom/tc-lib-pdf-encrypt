<?php
/**
 * RunLength.php
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
 * Com\Tecnick\Pdf\Filter\Type\RunLength
 *
 * RunLengthe
 * Decompresses data encoded using the zlib/deflate compression method,
 * reproducing the original text or binary data.
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfFilter
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-filter
 */
class RunLength
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
        // data length
        $data_length = strlen($data);
        $idx = 0;
        while ($idx < $data_length) {
            // get current byte value
            $byte = ord($data[$idx]);
            if ($byte == 128) {
                // a length value of 128 denote EOD
                break;
            } elseif ($byte < 128) {
                // if the length byte is in the range 0 to 127
                // the following length + 1 (1 to 128) bytes shall be copied literally during decompression
                $decoded .= substr($data, ($idx + 1), ($byte + 1));
                // move to next block
                $idx += ($byte + 2);
            } else {
                // if length is in the range 129 to 255,
                // the following single byte shall be copied 257 - length (2 to 128) times during decompression
                $decoded .= str_repeat($data[($idx + 1)], (257 - $byte));
                // move to next block
                $idx += 2;
            }
        }
        return $decoded;
    }
}

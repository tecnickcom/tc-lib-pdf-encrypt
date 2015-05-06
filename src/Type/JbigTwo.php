<?php
/**
 * JbigTwo.php
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
 * Com\Tecnick\Pdf\Filter\Type\JbigTwo
 *
 * JbigTwo
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfFilter
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-filter
 */
class JbigTwo
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
        $data = null;
        throw new PPException('~ this decoding method has not been yet implemented');
    }
}

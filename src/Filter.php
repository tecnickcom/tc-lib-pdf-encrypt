<?php
/**
 * Filter.php
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

namespace Com\Tecnick\Pdf\Filter;

use \Com\Tecnick\Pdf\Filter\Exception as PPException;

/**
 * Com\Tecnick\Pdf\Filter\Filter
 *
 * PHP class for decoding common PDF filters (PDF 32000-2008 - 7.4 Filters)
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfFilter
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-filter
 */
class Filter
{
    /**
     * Define a list of available filter decoders.
     *
     * @var array
     */
    private static $filtermap = array(
        'ASCIIHexDecode'   => 'AsciiHex',
        'ASCII85Decode'    => 'AsciiEightFive',
        'LZWDecode'        => 'Lzw',
        'FlateDecode'      => 'Flate',
        'RunLengthDecode'  => 'RunLength',
        'CCITTFaxDecode'   => 'CcittFax',
        'JBIG2Decode'      => 'JbigTwo',
        'DCTDecode'        => 'Dct',
        'JPXDecode'        => 'Jpx',
        'Crypt'            => 'Crypt',
    );

    /**
     * Decode data using the specified filter type.
     *
     * @param string $filter Filter name.
     * @param string $data   Data to decode.
     *
     * @return string  Decoded data string.
     */
    public function decode($filter, $data)
    {
        if (empty($filter)) {
            return $data;
        }
        if (!isset(self::$filtermap[$filter])) {
            throw new PPException('unknown filter: '.$filter);
        }
        $class = '\\Com\\Tecnick\\Pdf\\Filter\\Type\\'.self::$filtermap[$filter];
        $obj = new $class;
        return $obj->decode($data);
    }

    /**
     * Decode the input data using multiple filters
     *
     * @param array  $filters Array of decoding filters to apply in order
     * @param string $data    Data to decode.
     *
     * @return string Decoded data
     */
    public function decodeAll($filters, $data)
    {
        foreach ($filters as $filter) {
            $data = $this->decode($filter, $data);
        }
        return $data;
    }
}

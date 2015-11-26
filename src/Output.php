<?php
/**
 * Output.php
 *
 * @since       2008-01-02
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Com\Tecnick\Pdf\Encrypt;

/**
 * Com\Tecnick\Pdf\Encrypt\Output
 *
 * PHP class for output encrypt PDF object
 *
 * @since       2008-01-02
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
abstract class Output
{
    /**
     * Get the PDF encryption block
     *
     * @param int $objid This PDF Object number
     *
     * return string
     */
    public function getPdfEncryptionObj($objid)
    {
        $this->setMissingValues();
        $this->encryptdata['objid'] = $objid;
        $out = $this->encryptdata['objid'].' 0 obj'."\n";
        $out .= '<<';
        $out .= ' /Filter /'.$this->encryptdata['Filter'];
        if (!empty($this->encryptdata['SubFilter'])) {
            $out .= ' /SubFilter /'.$this->encryptdata['SubFilter'];
        }
        // V is a code specifying the algorithm to be used in encrypting and decrypting the document
        $out .= ' /V '.$this->encryptdata['V'];
        // The length of the encryption key, in bits. The value shall be a multiple of 8, in the range 40 to 256
        $out .= ' /Length '.$this->encryptdata['Length'];
        if ($this->encryptdata['V'] >= 4) {
            $out .= $this->getCryptFilter();
            // The name of the crypt filter that shall be used by default when decrypting streams.
            $out .= ' /StmF /'.$this->encryptdata['StmF'];
            // The name of the crypt filter that shall be used when decrypting all strings in the document.
            $out .= ' /StrF /'.$this->encryptdata['StrF'];
            /*
            if (!empty($this->encryptdata['EFF'])) {
                // The name of the crypt filter that shall be used when encrypting embedded file streams
                // that do not have their own crypt filter specifier.
                $out .= ' /EFF /'.$this->encryptdata['EFF'];
            }
            */
        }
        $out .= $this->getAdditionalEncDic();
        $out .= ' >>';
        $out .= "\n".'endobj';
        return $out;
    }

    /**
     * Get Crypt Filter section
     *
     * A dictionary whose keys shall be crypt filter names
     * and whose values shall be the corresponding crypt filter dictionaries.
     *
     * @return string
     */
    protected function getCryptFilter()
    {
        $out = '';
        $out .= ' /CF <<';
        $out .= ' /'.$this->encryptdata['StmF'].' <<';
        $out .= ' /Type /CryptFilter';
        // The method used
        $out .= ' /CFM /'.$this->encryptdata['CF']['CFM'];
        if ($this->encryptdata['pubkey']) {
            $out .= ' /Recipients [';
            foreach ($this->encryptdata['Recipients'] as $rec) {
                $out .= ' <'.$rec.'>';
            }
            $out .= ' ]';
            $out .= ' /EncryptMetadata '.$this->getBooleanString($this->encryptdata['CF']['EncryptMetadata']);
        }
        // The event to be used to trigger the authorization
        // that is required to access encryption keys used by this filter.
        $out .= ' /AuthEvent /'.$this->encryptdata['CF']['AuthEvent'];
        if (!empty($this->encryptdata['CF']['Length'])) {
            // The bit length of the encryption key.
            $out .= ' /Length '.$this->encryptdata['CF']['Length'];
        }
        $out .= ' >> >>';
        return $out;
    }

    /**
     * get additional encryption dictionary entries for the standard security handler
     *
     * @return string
     */
    protected function getAdditionalEncDic()
    {
        $out = '';
        if ($this->encryptdata['pubkey']) {
            if (($this->encryptdata['V'] < 4) && !empty($this->encryptdata['Recipients'])) {
                $out .= ' /Recipients [';
                foreach ($this->encryptdata['Recipients'] as $rec) {
                    $out .= ' <'.$rec.'>';
                }
                $out .= ' ]';
            }
        } else {
            $out .= ' /R';
            if ($this->encryptdata['V'] == 5) { // AES-256
                $out .= ' 5';
                $out .= ' /OE ('.$this->escapeString($this->encryptdata['OE']).')';
                $out .= ' /UE ('.$this->escapeString($this->encryptdata['UE']).')';
                $out .= ' /Perms ('.$this->escapeString($this->encryptdata['perms']).')';
            } elseif ($this->encryptdata['V'] == 4) { // AES-128
                $out .= ' 4';
            } elseif ($this->encryptdata['V'] < 2) { // RC-40
                $out .= ' 2';
            } else { // RC-128
                $out .= ' 3';
            }
            $out .= ' /O ('.$this->escapeString($this->encryptdata['O']).')';
            $out .= ' /U ('.$this->escapeString($this->encryptdata['U']).')';
            $out .= ' /P '.$this->encryptdata['P'];
            $out .= ' /EncryptMetadata '.$this->getBooleanString($this->encryptdata['EncryptMetadata']);
        }
        return $out;
    }

    /**
     * Return a string representation of a boolean value
     *
     * @param bool $value Value to convert
     *
     * @return string
     */
    protected function getBooleanString($value)
    {
        return ($value ? 'true' : 'false');
    }

    /**
     * Set missing values
     */
    protected function setMissingValues()
    {
        if (!isset($this->encryptdata['EncryptMetadata'])) {
            $this->encryptdata['EncryptMetadata'] = true;
        }
        if (!empty($this->encryptdata['CF'])) {
            if (!isset($this->encryptdata['CF']['EncryptMetadata'])) {
                $this->encryptdata['CF']['EncryptMetadata'] = true;
            }
        }
    }
}

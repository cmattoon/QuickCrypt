<?php
/**
 * QuickCrypt is a collection of functions to help with hashing passwords.
 *
 * @author Curtis Mattoon <cmattoon@cmattoon.com>
 * @license MIT
 * @license http://opensource.org/licenses/MIT
 * @version 1.0.0
 *
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. 
 *
 */
class QuickCrypt {

    /**
     * The default length for random passwords
     * @var int $defaultRandomPasswordLength
     * @access public
     */
    public $defaultRandomPasswordLength = 8;

    /**
     * Class settings
     * @var array $settings
     * @access public
     */
    public $settings = array();

    /**
     * Measures time to create a hash (for benchmarking/testing)
     * @var float $timeToHash
     * @access private
     */
    private $timeToHash = 0;
    
    /**
     * The Bcrypt work factor. Some sources [citation needed] recommend using
     * date('Y'). Adjust this so hashing takes 0.25 < t < 0.5 on your server.
     * @var int $workFactor
     * @access private
     */
    private $workFactor = 13;

    /**
     * The prefix for Bcrypt. Set in quickTests()
     * @var string $BCprefix
     * @access public
     */
    public $BCprefix = '2y';

    /**
     * Which hash_hmac algorithm to fall back upon if Mcrypt isn't available
     * @var string $HMACalgorithm
     * @access public
     */
    public $HMACalgorithm = 'sha256';

    /**
     * Is OpenSSL available?
     * @var bool $openSSL
     * @access private
     */
    private $openSSL = False;

    /**
     * Is the Mcrypt extension loaded? (Kinda goes hand-in-hand with $mcryptCreateIV I guess)
     * @var bool $mcryptEnabled
     * @access private
     */
    private $mcryptEnabled = False;

    /**
     * Is mcrypt_create_iv available?
     * @var bool $mcryptCreateIV
     * @access private
     */
    private $mcryptCreateIV = False;
    
    /**
     * Is hash_hmac enabled?
     * @var bool $hmacEnabled
     * @access private
     */
    private $hmacEnabled = False;

    /**
     * Constructor.
     * Performs quick tests of server capabilities and sets $settings
     * @todo - Make tests suck less
     * @todo - Incorporate $settings into constructor param and parse
     */
    public function __construct() {
        $this->quickTest();
        $this->settings = array(
            'expand_password' => True,
            'warn_on_mt_rand' => True,
            'exception_mt_rand' => False,
            'allow_microtime_salt' => False
        );
        
    }

    /**
     * Expands a short password to a 40-char string.
     * 
     * I'd love input from someone who really knows what they're doing on this.
     * Like everything else, it started out innocently enough and seemed like a
     * good idea at the time, but now I'm having my doubts.
     *
     * Initially, I had expanded it only with sha1() to prevent issues with UTF-8
     * on older systems (PHP < 5.3.7). Then, I realized that it reduced the
     * effective keyspace to 16^40 characters, so I  appended it to the hash so 
     * as to retain the full keyspace. This breaks the UTF-8 protection. If you
     * are worried about the UTF-8 issue on an older system, either remove the
     * appended "$password . $salt", or use something other than mcrypt.
     *
     * Now I'm wondering if the base64 or sha1 functions are just as vulnerable
     * to multibyte encodings. I'm going to research this more, but this is a fair
     * warning that you should look at your system and possibly modify this 
     * function if needed. Again, comments are welcome.
     *
     * @link http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-2483
     * @link http://www.php.net/security/crypt_blowfish.php
     *
     * @param string $password The plaintext password to hash
     * @param string $salt A salt
     *
     * @return string A 40 char (160-bit) hash of the inputs, plus the appended
     *  $password and $salt.
     */
    public function expandPassword($password, $salt) {
        return sha1($password . $salt) . $password . $salt;
    }
    
    /** 
     * Generates a hash of a password.
     *
     * This method will try to use Bcrypt if it's available, followed by
     * hash_hmac and finally SHA-1. 
     *
     * @param string $plaintext_password
     * 
     * @return string The final hash
     */
    public function hash($plaintext_password) {
        try {
            $salt = $this->getSalt();
        } catch (Exception $e) {
            $this->log('Caught Exception: (' . $e->getMessage() . ')');
            return False;
        }
        
        // Key expansion
        if ($this->settings['expand_password']) {
            $plaintext_password = $this->expandPassword($plaintext_password, $salt);
        }

        if ($this->mcryptEnabled) {
            if (CRYPT_BLOWFISH == 1) {
                $salt = '$'.$this->BCprefix .'$'. str_pad($this->workFactor, 2, '0', STR_PAD_LEFT) . '$' . $salt;
                $time_start = microtime(True);
                $final_hash = crypt($plaintext_password, $salt);
                $this->timeToHash = microtime(True) - $time_start;
            } elseif (CRYPT_SHA512 == 1) {
                // Add support later
            } elseif (CRYPT_SHA256 == 1) {
                // Add support later
            } else {
                $msg = 'I dont know what hash algorithm to use!';
                $this->log($msg);
                throw new Exception($msg);
            }
        } elseif ($this->hmacEnabled) {
            // If Mcrypt is not available, resort to hash_hmac()
            $final_hash = '$hm$'.$salt.'$'.hash_hmac($this->HMACalgorithm, $plaintext_password, $salt);
        } else {
            $this->log('WARNING: Constructing a sha1 hash!');
            // At least protect against length extension attacks on SHA1
            $final_hash = sha1( sha1($plaintext_password . $salt) . $plaintext_password . $salt);
        }

        return $final_hash;         
    }
    /**
     * Determines if $stored_hash is a valid hash of $password.
     *
     * If you're using old hash types (e.g., MD5), you'll need to add support
     * for your specific salting/hashing algorithm.
     *
     * @param string $password A plaintext password
     * @param string $stored_hash The hash that's (probably) stored in the database.
     *
     * @return bool Whether or not the password matches the hash
     */
    public function checkPassword($password, $stored_hash) {
        $salt = '';
        $parts = explode('$', $stored_hash);
        
        // This could be re-written with the results of self::detectHashType() and a substr,
        // but I'm leaving it as-is for the time being.
        switch ($parts[1]) {
            case '2a':
            case '2x':
            case '2y':
                $salt = substr($parts[3], 0, 22);
                if ($this->settings['expand_password']) {
                    $password = $this->expandPassword($password, $salt);
                }
                
                if (strpos($stored_hash, '$2a$') === 0 && version_compare(PHP_VERSION, '5.3.7') >= 0) {
                    // Replace with a 2x if it's an old Bcrypt hash. Consider re-hashing with 2y
                    $stored_hash = '$2x$' . substr($stored_hash, 4);
                }
                
                $check_hash = crypt($password, $stored_hash);
                break;
            case 'hm':
                // Keyed HMAC
                $salt = $parts[2];
                if ($this->settings['expand_password']) {
                    $password = $this->expandPassword($password, $salt);
                }
                $check_hash = '$hm$'.$salt.'$'.hash_hmac($this->HMACalgorithm, $password, $salt);
                break;
        }

        // Quick Check
        if (strlen($check_hash) !== strlen($stored_hash)) return False;

        /* String comparison is byte-by-byte, which could (in theory) result in
         * a timing attack. In this method, h1[i] and h2[i] are XOR'd together,
         * which will result in 1 if the chars differ. This "1" is in turn OR'd
         * into the result, which will remain "1". All characters are checked
         * before a result is returned, which helps to protect against a timing
         * attack.
         * I know there's a more efficient way of doing this, but it's pretty
         * straightforward (and I couldn't pass up a perfectly valid opportunity 
         * to use bitwise operators :) and now, more text to prevent that awkward
         * closing-parentheses-when-the-inner-text-ends-with-an-emoticon thing)
         */
        $check = 0;

        for ($i = 0; $i < strlen($stored_hash); $i++) {
            $check |= $stored_hash[$i] ^ $check_hash[$i];
        }
        
        return ($check === 0);
    }

    /**
     * This method generates a plaintext password of $length chars from $keyspace.
     * Useful for generating random passwords for password resets, etc. 
     *
     * If using chars like <>'" be careful to print the output with htmlentities()
     * 
     * @param int $length The strlen of the password to be generated
     *  
     * @return string A plaintext password of $length chars
     */    
    public function getRandomPassword($length = 0, $keyspace = '') {
        if (empty($keyspace) || strlen($keyspace) < 16) { // Require keyspace of at least the hex chars
            $keyspace  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $keyspace .= strtolower($keyspace); //a-z
            $keyspace .= '1234567890';
            $keyspace .= '!@#$%^&*()_+-=\'"';
            //$keyspace .= '[]{}\|<>?,./~'; // Commented to prevent issues with <>'" chars with out-of-box use.
        }

        if ((int)$length == 0) {
            $length = $this->defaultRandomPasswordLength;
        }

        $password = '';

        while (strlen($password) < $length) {
            $idx = rand(0, strlen($keyspace));
            $password .= $keyspace[$idx];
        }

        return $password;
    }

    /**
     * Generates a 22-char salt to be used in hashing the password. 
     * @todo Add more options (e.g., generate n-char salt based on char:byte ratio (noting base64 conversion))
     *
     * @return string A 22-char base64-encoded string
     */    
    public function getSalt() {
        try {
            $random = $this->getRandomBytes(32);
        } catch (Exception $e) {
            $this->log('Caught Exception: (' . $e->getMessage() . ')');
            if (!$this->settings['allow_microtime_salt']) throw new Exception('Resorting to microtime for salt');
            $random = sha1(microtime(True));
        }

        return substr(strtr($this->encode64($random), '+', '.'), 0, 22);
    }

    /** 
     * Retrieves an $bytes-byte stream of pseudorandom data
     *
     * This function returns a $bytes sized string of pseudorandom bits
     * it will attempt to use progressively less-random sources, depending on 
     * what functions the system has available. Using /dev/random can cause the
     * script to hang as it waits for entropy, so it's using urandom. If you
     * desire something more secure, consider running something like 
     * rngd-tools in the background.
     * 
     * @param int $bytes (Optional) The number of pseudorandom bytes to return.
     * @return string A string of pseudorandom bits.
     */
    public function getRandomBytes($bytes = 32) {
        $bitstream = Null;
        if ($this->openSSL) {
            $bitstream = openssl_random_pseudo_bytes($bytes);
        } elseif ($this->mcryptCreateIV) {
            $bitstream = mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
        } else {
            $f = @fopen('/dev/urandom', 'rb');
            $f= False;
            if ($f !== False) {
                $bitstream = @fread($f, $bytes);
                $bitstream = bin2hex($bitstream);
            }
        }
            
        if ($bitstream === Null) { // Last attempt!
            if ($this->settings['exception_mt_rand']) throw new Exception('mt_rand() not a valid source of random bits!');
            if ($this->settings['warn_on_mt_rand']) $this->log('[Crypto] WARNING: Using mt_rand() as source of random bits!');
            
            while (mb_strlen($bitstream) < $bytes) {
                $bitstream .= pack('H*', base_convert(decbin(mt_rand()), 2, 10));
            }
        }
        
        if ($bitstream === Null) {
            throw new Exception('No valid source for random bits!');
        } else {
            $bitstream = mb_strcut($bitstream, 0, $bytes);
            return $bitstream;
        }
    }    


    /**    
     * It should go without saying this is not a definitive function. 
     * It's designed to allow a mixture of hash types to be supported by this class 
     * (e.g., during migration from one hash type to another. 
     *
     * @param string $hash The hash to detect (hex-encoded; raw output of hash won't work)
     * @return string|bool String of hash type if found, False if unknown.
     *
     * @todo The HMAC hash should store another identifier to indicate which algorithm was used.
     */
    public function detectHashType($hash) {
        // The common ones from PHP are listed as cases. If you KNOW your
        //  old codebase used (e.g., MD2), you'll want to adjust the code accordingly

        switch (strlen($hash)) {
            case 35:
                return 'md5'; // Or MD2, MD4, etc.
            case 40:
                return 'sha1'; // Potentially RIPEMD-160, HAS-160, etc.
        }
        
        if (strpos($hash, '$') !== False) {
            $parts = explode('$', $hash);
            switch ($parts[1]) {
                case '2a':
                case '2x':
                case '2y':
                    return 'bcrypt';
                case 'hm':
                    return 'hmac';
            }
        }

        return False;
    }
    
    
    /**
     * Determines if the hash is older than what the system can produce now.
     *
     * This is useful for automatically updating passwords upon login, either
     * after an upgrade from PHP < 5.3.7 or when changing the work factor for
     * Blowfish. This really should be reviewed and perhaps modified based on 
     * what kinds of hashes you have in your database.
     *
     * @param string $hash
     * @return bool Whether or not the hash is the best type it can be.
     */
    public function isOldHash($hash) {
        switch ($this->detectHashType($hash)) {
            case 'md5':
            case 'sha1':
                return True;
            case 'hmac':
                return $this->blowfishAvailable;
            case 'bcrypt':
                // Check the work factor
                $parts = explode('$', $hash);
                // If the work factor has increased since $hash was generated OR it's using a legacy bcrypt prefix (and the new $2y$ is available
                return (((int)$parts[2] < $this->workFactor) || (in_array($parts[1], array('2a','2x')) && version_compare(PHP_VERSION, '5.3.7') >= 0));
            default:
                return False;
        }
    }    


    /**
     * Returns a BSD-style base64-encoded string
     * 
     * The base64_decode function in PHP uses the standard algorithm, 
     * while Blowfish uses the BSD implementation (to maintain POSIX compatability). 
     *
     * <nerdStuff>
     *  Bcrypt will handle this fine on newer versions (> 5.3), but this will 
     *  ensure that it works on the older versions. The last character in the 
     *  encoded string will only represent 2 bits, since it's a 128-bit (16 byte) 
     *  salt (21x 6 bits + 2bits). New Bcrypt versions will correct the 4 unused 
     *  bits to non-zero, but it will break on older versions. Also, this gives 
     *  an additional byte of entropy.
     * </nerdStuff>
     *
     * @param string $input The string to encode
     * 
     * @return string The (BSD) base64-encoded string
     */
    public function encode64($input) {
		$charset = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $output = '';
		$i = 0;

		while (True) {
			$c1 = ord($input[$i++]);
			$output .= $charset[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			
			if ($i >= 16) {
				$output .= $charset[$c1];
				break;
			}

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $charset[$c1];
			$c1 = ($c2 & 0x0f) << 2;

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $charset[$c1];
			$output .= $charset[$c2 & 0x3f];
		}

		return $output;    
    }
    
    /**
     * Performs some basic tests on instantiation.
     *
     * Once this class is set up on the server, you can safely remove it from
     * the constructor and/or entirely from this file. IF YOU DO THIS, MAKE SURE
     * YOU SET THE APROPRIATE VALUES FOR THESE PROPERTIES.
     *
     */
    public function quickTest() {
        $this->openSSL = function_exists('openssl_random_pseudo_bytes');
        $this->mcryptCreateIV = function_exists('mcrypt_create_iv');
        
        if (extension_loaded('mcrypt')) {
            // Bcrypt (Blowfish) test
            if (CRYPT_BLOWFISH == 1) {
                $this->mcryptEnabled = True;
    
                if (version_compare(PHP_VERSION, '5.3.7') >= 0) {
                    $this->BCprefix = '2y';
                } else{
                    $this->BCprefix = '2a';
                }
            }            
        } elseif (function_exists('hash_hmac')) {
            // Only check this if mcrypt isn't loaded
            $this->hmacEnabled = True;
        }
    }

    /**
     * Getter for work factor.
     * @return int The current work factor
     */
    public function getWorkFactor() {
        return $this->workFactor;
    }
    
    /** 
     * Sets a new work factor. This should generally be unnecessary. Modifying the
     * class occasionally would be a better way to ensure consistency across your
     * application.
     * @param int $new_work_factor An int x where 4 <= x <= 32
     * @param bool $if_greater_than_current Only update the work factor if it's 
        greater than the current one. Prevents accidentally decreasing the work factor
     * @return int The current work factor.
     */
    public function setWorkFactor($new_work_factor, $if_greater_than_current = True) {
        $work_factor = (int)$new_work_factor;
        if (($work_factor < 4 || $work_factor > 32) || ($if_greater_than_current === True && $this->workFactor <= $work_factor)) {
            // Don't set the work factor. I phrased it this way for readablilty.
        } else {
            $this->workFactor = $work_factor;
        }
        
        return $this->workFactor;
    }

    /**
     * Getter function for relevant stats. 
     * @todo expand this
     * @return array An associative array with keys 'work_factor' and 'time_to_hash'
     */
    public function getStatistics() {
        return array(
            'work_factor' => $this->workFactor,
            'time_to_hash' => $this->timeToHash
        );
    }

    /**
     * Pass-through function for logging.
     * @param $message
     * @return void
     */
    private function log($message) {
        error_log('[QuickCrypt Message] ' . $message);
    }
}

?>

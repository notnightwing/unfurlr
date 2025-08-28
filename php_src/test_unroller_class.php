<?php

class Url_Unroller{


    protected static $_fav_domains = array();
    protected static $_cookie_file = null;
    protected $_redirect_codes = array('301', '302', '303', '307');
    protected $_max_redirects = 10;
    protected $_timeout = 10;
    protected $_connect_timeout = 10;
    protected $_ch;
    protected $_ua;
    protected $_extras = false;
    protected $_domains = array();

    public function __construct($ua=null, $extras=false) {
        $this->_ch = curl_init();

        if (is_bool($extras)){
            //for unfurlr extra annotations
            $this->_extras = $extras;
        }
        if ($this->_extras){
            require_once('geshi.php');
        }


        if ($ua!==null){
            $uas = unserialize(file_get_contents(AVESTA_ROOT_DIR . '/data/ua_strings.ser'));

            if ($ua == null || !isset($uas[$ua])){
                $idx = array_rand($uas);
                $idx2 = array_rand( $uas[$idx] );
                $this->_ua = $uas[$idx][$idx2];
            } else {
                $idx = array_rand( $uas[$ua] );
                $this->_ua = $uas[$ua][$idx];
            }
        } else {
            $this->_ua = $ua;
        }

        curl_setopt_array($this->_ch, array(
            CURLOPT_HEADER          => false,
            CURLOPT_SSL_VERIFYHOST  => false,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_CONNECTTIMEOUT  => $this->_connect_timeout,
            CURLOPT_TIMEOUT         => $this->_timeout
        ));

        $headers = array();
        //let's screw with them and try to give a fake ip, too
        $ip = rand(1,254).'.'.rand(1,254).'.'.rand(1,254).'.'.rand(1,254);

        foreach( array('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_TRUE_CLIENT_IP' ) as $h){
            $headers[] = $h . ': ' . $ip;
        }

        //some other "normal" headers browsers would present...
        $headers[] = 'Accept: */*';
        $headers[] = 'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3';
        $headers[] = 'Accept-Language:en-US,en;q=0.8,es;q=0.6';
        $headers[] = 'Cache-Control: max-age=0';
        $headers[] = 'Connection: keep-alive';
        $headers[] = 'User-Agent: ' . $this->_ua;

        self::$_cookie_file = AVESTA_ROOT_DIR . '/cache/cookies_' . Avesta::uniqueID();
        @touch(self::$_cookie_file);

        curl_setopt_array($this->_ch, array(
            CURLOPT_HTTPHEADER      => $headers,
            CURLINFO_HEADER_OUT     => true,
            CURLOPT_RANDOM_FILE     => '/dev/urandom',
            CURLOPT_COOKIEFILE      => self::$_cookie_file,
            CURLOPT_COOKIEJAR       => self::$_cookie_file,
            CURLOPT_COOKIESESSION   => true
        ));
    }


    public function _shutdown() {
        @curl_close($this->_ch);
        unset($this->_ch);
        @unlink(self::$_cookie_file);
    }

    public function follow_it($url) {
        $i=0;
        $sessions = array();
        $referrer = null;
        while(1) {
            $parts = parse_url($url);
            $scheme = trim(strtolower($parts['scheme']));
            if (!in_array($scheme, array('http','https'))) {
                return $sessions;
            }

            $host = trim(strtolower($parts['host']));

            if (!in_array($host, $this->_domains)) {
                $this->_domains[] = $host;
            }

            if (Avesta_Validation::isValid('ipv4|required', $host)) {
                if (!Avesta_Validation::isValid('ipv4(0)', $host) ) {
                    Avesta_Log::info('NO Private IPs (2) '. $host, 'follow_errors');
                    return $sessions;                    
                }
            }

            if (!Avesta_Validation::isValid('ipv4',$host)) {
                $ip = trim(gethostbyname($host));
                if (!Avesta_Validation::isValid('ipv4(0)',$ip) && Avesta_Validation::isValid('ipv4(1)',$ip)) {
                    Avesta_Log::info('NO Private IPs (2) '. $host .' | '.$ip, 'follow_errors');
                    return $sessions;
                }
            }

            curl_setopt_array($this->_ch, array(
                CURLOPT_FOLLOWLOCATION  => false,
                CURLOPT_HEADER          => true,
                CURLOPT_URL             => $url
            ));

            if($referrer != null) {
                curl_setopt($this->_ch, CURLOPT_REFERER, $referrer);
            }

            $referrer = $url;
            $result = curl_exec($this->_ch);
            $code = curl_getinfo($this->_ch, CURLINFO_HTTP_CODE);
            $header_out = curl_getinfo($this->_ch, CURLINFO_HEADER_OUT);
            list($headers, $data) = explode("\r\n\r\n", $result, 2);

            if ($this->_extras){
                $sessions[$i] = $this->analyze($url, $code, trim($headers), trim($data));
                $sessions[$i]['ua'] = $this->_ua;

                //real browsers will also try to get your favicon
                if (!in_array($host,self::$_fav_domains)){
                    curl_setopt($this->_ch, CURLOPT_URL, 'http://'.$host.'/favicon.ico');
                    $result = curl_exec($this->_ch);
                    $fav_code = curl_getinfo($this->_ch, CURLINFO_HTTP_CODE);
                    if(intval($fav_code/100)==2){
                        self::$_fav_domains[] = $host;
                    }
                }

            }
            $sessions[$i]['url'] = $url;
            if($i > $this->_max_redirects) {
                $this->_shutdown();

                return $sessions;
            }
            
            //let's see if maybe we got a 200 with a meta redirect in it...
            preg_match('/meta http-equiv="refresh" content="([\d.]+);URL=(.*)"/miU', $data, $meta_redir);

            if($meta_redir[2]) {
                $host = parse_url($meta_redir[2], PHP_URL_HOST);
                if(!$host) {
                    $url = $url . '/' . trim($meta_redir[2]);
                } else {
                    $url = trim($meta_redir[2]);
                }
            } elseif (!in_array($code, $this->_redirect_codes)){
                $this->_shutdown($this->_ch);

                return $sessions;
            } else {
                preg_match('/Location: (.*)/i', $headers, $matches);
                $host = parse_url($matches[1],PHP_URL_HOST);

                if(!$host) {
                    $url = $url . '/' . trim($matches[1]);
                } else {
                    $url = trim($matches[1]);
                }
            }

            $i++;
        }
    }

    public function analyze($url, $code, $headers, $response){
        $family = intval($code/100);
        $data = array('code'=>$code, 'code_family'=>$family, 'code_message'=>Zend_Http_Response::responseCodeAsText($code));

        foreach(explode("\r\n", $headers) as $header){
            list($h, $d) = explode(':', $header,2);
            if (!$h){
                $data['headers'] .= '<br/>';
                continue;
            }
            if (strpos($h, 'HTTP')===0){
                $data['headers'] .= htmlentities($h).'<br/>';
                continue;
            }
            $d = trim("".$d);

            $html = '<a href="http://www.cs.tut.fi/~jkorpela/http.html?x='.time().'#'.rawurlencode($h).'" target="_blank">'.$h.'</a>: '.htmlentities($d).'<br/>';
            $data['headers'] .= $html;
        }

        $tmp_file = tempnam('/tmp/', 'content');
        file_put_contents($tmp_file, $response);

        list($mime, $ext) = MC_Mime::identify($tmp_file);
        if ($family==2){
            $content = UR_Cache::get('content', $url);
            if (strpos($mime,'text/')===0){
                $geshi = new GeSHi($response, 'html5');
                $data['response'] = $geshi->parse_code();
                if (!$content){
                    $content = $this->analyzeContent($response);
                }
            } else {
                $data['response'] = 'File of type: '.$mime .' found.';
                $content['title'] = 'File of type: '.$mime .' found.';
            }
            UR_Cache::set('content', $url, $content);
            $data['content'] = $content;
            $data['code_message'] = 'content retrieved, now we should analyze it...';
        }
        return $data;

    }

    public function analyzeContent($html){
        $doc = Avesta_HTML::parse($html);
        $data = array();
        $cached_domains = array();
        if ($doc){
            $embeds = $doc->select('embed');
            $data['embed_total'] = sizeof($embeds);

            $objects = $doc->select('object');
            $data['object_total'] = sizeof($objects);

            $scripts = $doc->select('script');
            if ($scripts){
                foreach($scripts as $script){
                    if ($script->attrs['src']){
                        $data['script_srcs'][] = trim($script->attrs['src']);
                        $host = parse_url($script->attrs['src'],PHP_URL_HOST);
                        if ($host && !in_array($host,$this->_domains)){
                            $this->_domains[] = $host;
                        }
                    } else {
                        $geshi = new GeSHi(trim($script->innerHtml()) , 'javascript');
                        $data['script_code'][] = $geshi->parse_code();
                    }
                }
                $data['script_total']++;
            } else {
                $data['script_total'] = 0;
            }

            $title = $doc->select('head title');
            if ($title){
                $data['title'] = $title[0]->innerHtml();
            } else {
                $data['title'] = '<span class="error">No Page Title</span>';
            }
        }

        $parser = new MC_LinkParser_Html(array($this, 'gatherDomains'));
        $parser->parse($html);
        $i = 0;
        $to_check = array();
        foreach($this->_domains as $domain){
            $dom = UR_Cache::get('mywot', $domain);
            if (!$dom){
                $to_check[] = $domain;
            } else {
                $cached_domains[$domain] = $dom;
            }
        }
        if (sizeof($to_check)>0){
            $chk_str = implode('/',$to_check);
            $response = file_get_contents('http://api.mywot.com/0.4/public_link_json?hosts='.$chk_str);
            if ($response){
                $domains = json_decode($response,true);
                $i = 0;
                foreach($domains as $domain){
                    $cached_domains[ $to_check[$i] ] = $domain;
                    UR_Cache::set('mywot', $to_check[$i], $domain);
                    $i++;
                }
            }
        }
        foreach($this->_domains as $domain){
            $data['domains'][] = $cached_domains[$domain];
        }
        return $data;

    }

    public function gatherDomains($url) {
        $host = strtolower(parse_url($url,PHP_URL_HOST));
        if (!in_array($host,$this->_domains)){
            $this->_domains[] = $host;
        }
    }


    /** wot display helpers  */
    public static function wotRows($domain){
        $tbl = '<tr><td rowspan="'.(sizeof($domain)-1).'">'.$domain['target'].'<br/>
                <a target="_blank" href="http://www.mcafee.com/threat-intelligence/domain/default.aspx?domain='.$domain['target'].'">
                <img src="http://www.mcafee.com/img/mcafee-logo-sm.gif" border=0/>check</a>
                </td>';

        if (!$domain['0'] && !$domain['1'] && !$domain['2'] && !$domain['4']){
            $tbl .= '<td colspan="3"><div class="error"><strong>No <a href="http://www.mywot.com/">Web of Trust</a> analysis found - that could mean a very bad thing, or nothing at all.</strong></div></td></tr>';
            return $tbl;
        }
        $need_tr = false;
        if($domain['0']){
            $tbl .= '<td>Trustworthiness</td>
                    <td><img src="'.self::wotRimg($domain['0'][0]).'"> ('.$domain['0'][0].')</td>
                    <td><img src="'.self::wotCimg($domain['0'][1]).'"> ('.$domain['0'][1].')</td></tr>';
            $need_tr = true;
        }
        if($domain['1']){
            if ($need_tr) $tbl .= '<tr>';
            $tbl .= '<td>Vendor reliability</td>
                    <td><img src="'.self::wotRimg($domain['1'][0]).'"> ('.$domain['1'][0].')</td>
                    <td><img src="'.self::wotCimg($domain['1'][1]).'"> ('.$domain['1'][1].')</td></tr>';
            $need_tr = true;
        }
        if($domain['2']){
            if ($need_tr) $tbl .= '<tr>';
            $tbl .= '<td>Privacy</td>
                    <td><img src="'.self::wotRimg($domain['2'][0]).'"> ('.$domain['2'][0].')</td>
                    <td><img src="'.self::wotCimg($domain['2'][1]).'"> ('.$domain['2'][1].')</td></tr>';
            $need_tr = true;
        }

        if($domain['4']){
            if ($need_tr) $tbl .= '<tr>';
            $tbl .= '<td>Child safety</td>
                    <td><img src="'.self::wotRimg($domain['4'][0]).'"> ('.$domain['4'][0].')</td>
                    <td><img src="'.self::wotCimg($domain['4'][1]).'"> ('.$domain['4'][1].')</td></tr>';
        }

        return $tbl;

    }

    public static function wotRimg($r){
        if ($r<20){
            return '/img/wot/16_verypoor.png';
        }elseif($r<40){
            return '/img/wot/16_unsatisfactory.png';
        }elseif($r<60){
            return '/img/wot/16_poor.png';
        }elseif($r<80){
            return '/img/wot/16_good.png';
        } else {
            return '/img/wot/16_excellent.png';
        }
    }

    public static function wotCimg($c){
        if ($c<=0){
            return '/img/wot/Confidence_0.png';
        }elseif($c<6){
            return '/img/wot/Confidence_1.png';
        }elseif($c<12){
            return '/img/wot/Confidence_2.png';
        }elseif($c<23){
            return '/img/wot/Confidence_3.png';
        }elseif($c<34){
            return '/img/wot/Confidence_4.png';
        } else {
            return '/img/wot/Confidence_5.png';
        }
    }

    /** blah blah blah, getters & setters because college */

    public function setMaxRedirects($max) {
        if(isset($max)) {
            $this->_max_redirects = $max;

            return true;
        }

        return false;
    }

    public function getMaxRedirects() {
        return $this->_max_redirects;
    }

    public function setRedirectCodes($codes) {
        if(isset($codes) && count($codes) > 0) {
            $this->_redirect_codes = $codes;

            return true;
        }

        return false;
    }

    public function getRedirectCodes() {
        return $this->_redirect_codes;
    }

    public function setTimeout($timeout) {
        if (isset($timeout)) {
            $this->_timeout = $timeout;

            return true;
        }

        return false;
    }

    public function getTimeout() {
        return $this->_timeout;
    }

    public function setConnectTimeout($timeout) {
        if (isset($timeout)) {
            $this->_connect_timeout = $timeout;

            return true;
        }

        return false;
    }

    public function getConnectTimeout() {
        return $this->_connect_timeout;
    }

    public function setUA($ua) {
        if(isset($ua)) {
            $this->_ua = $ua;

            return true;
        }

        return false;
    }

    public function getUA() {
        return $this->_ua;
    }

}

<?php
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
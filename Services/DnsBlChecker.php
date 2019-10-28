<?php

namespace App\Services;


use App\DnsblService;

class DnsBlChecker
{
    public static function check($host, $dns_blacklist = null)
    {
        if (is_null($dns_blacklist)) {
            $dns_blacklist = DnsblService::pluck('domain')->toArray();
        }
        $response = [];
        $host_revert = join(".", array_reverse(explode(".", $host)));
        foreach ($dns_blacklist as $dns) {
            if(!empty(@dns_get_record($host_revert . '.' . $dns, DNS_TXT)))
            $response[] = $dns;
        }

        return $response;
    }
}
<?php
declare(strict_types=1);

namespace ipad54\BedrockEditionClient\address;

use raklib\utils\InternetAddress;
use function gethostbyname;

final class ServerAddress{
	public static function create(string $ip, int $port, int $version = 4) : InternetAddress{
		return new InternetAddress(gethostbyname($ip), $port, $version);
	}
}
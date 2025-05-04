<?php
declare(strict_types=1);

namespace ipad54\BedrockEditionClient\network\raknet;

use pocketmine\utils\SingletonTrait;
use raklib\protocol\IncompatibleProtocolVersion;
use raklib\protocol\OfflineMessage;
use raklib\protocol\OpenConnectionReply1;
use raklib\protocol\OpenConnectionReply2;
use raklib\protocol\UnconnectedPong;
use function ord;

final class OfflinePacketPool{
	use SingletonTrait;

	private \SplFixedArray $packetPool;

	public function __construct(){
		$this->packetPool = new \SplFixedArray(256);

		$this->registerPacket(UnconnectedPong::$ID, UnconnectedPong::class);
		$this->registerPacket(OpenConnectionReply1::$ID, OpenConnectionReply1::class);
		$this->registerPacket(OpenConnectionReply2::$ID, OpenConnectionReply2::class);
		$this->registerPacket(IncompatibleProtocolVersion::$ID, IncompatibleProtocolVersion::class);
	}

	private function registerPacket(int $id, string $class) : void{
		$this->packetPool[$id] = new $class;
	}

	public function getPacketFromPool(string $buffer) : ?OfflineMessage{
		$pk = $this->packetPool[ord($buffer[0])];
		if($pk !== null){
			return clone $pk;
		}

		return null;
	}
}
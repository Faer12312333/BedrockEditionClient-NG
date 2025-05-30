<?php
declare(strict_types=1);

namespace ipad54\BedrockEditionClient\network\handler;

use ipad54\BedrockEditionClient\network\NetworkSession;
use pocketmine\network\mcpe\compression\ZlibCompressor;
use pocketmine\network\mcpe\handler\PacketHandler;
use pocketmine\network\mcpe\protocol\ClientToServerHandshakePacket;
use pocketmine\network\mcpe\protocol\NetworkSettingsPacket;
use pocketmine\network\mcpe\protocol\PlayStatusPacket;
use pocketmine\network\mcpe\protocol\RequestChunkRadiusPacket;
use pocketmine\network\mcpe\protocol\ResourcePackClientResponsePacket;
use pocketmine\network\mcpe\protocol\ResourcePacksInfoPacket;
use pocketmine\network\mcpe\protocol\ServerToClientHandshakePacket;
use pocketmine\network\mcpe\protocol\SetLocalPlayerAsInitializedPacket;
use pocketmine\network\mcpe\protocol\StartGamePacket;
use pocketmine\network\mcpe\protocol\types\CompressionAlgorithm;
use const PHP_INT_MAX;

final class PreSpawnPacketHandler extends PacketHandler{
	public function __construct(private NetworkSession $networkSession){ }

	public function handleServerToClientHandshake(ServerToClientHandshakePacket $packet) : bool{
		$this->networkSession->startEncryption($packet->jwt);

		$this->networkSession->sendDataPacket(ClientToServerHandshakePacket::create());
		return true;
	}

	public function handleResourcePacksInfo(ResourcePacksInfoPacket $packet) : bool{
		$this->networkSession->sendDataPacket(ResourcePackClientResponsePacket::create(ResourcePackClientResponsePacket::STATUS_COMPLETED, []));
		return true;
	}

	public function handleStartGame(StartGamePacket $packet) : bool{
		$this->networkSession->createPlayer($packet);

		$this->networkSession->sendDataPacket(RequestChunkRadiusPacket::create(5, 5));
		return true;
	}

	public function handlePlayStatus(PlayStatusPacket $packet) : bool{
		if($packet->status === PlayStatusPacket::PLAYER_SPAWN){
			$this->networkSession->sendDataPacket(SetLocalPlayerAsInitializedPacket::create($this->networkSession->getClient()->getId()));
			$this->networkSession->getPlayer()?->setSpawned(true);

			$this->networkSession->setHandler(null);

			$this->networkSession->getClient()->getLogger()->debug("Player was spawned");
		}
		return true;
	}

	public function handleNetworkSettings(NetworkSettingsPacket $packet) : bool{
		if($packet->getCompressionAlgorithm() !== CompressionAlgorithm::ZLIB){
			throw new \InvalidArgumentException("Unsupported compression algorithm");
		}
		$this->networkSession->setCompressor(new ZlibCompressor(ZlibCompressor::DEFAULT_LEVEL, ZlibCompressor::DEFAULT_THRESHOLD, PHP_INT_MAX));
		$this->networkSession->processLogin();
		return true;
	}
}
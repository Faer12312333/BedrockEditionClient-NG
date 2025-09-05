<?php
declare(strict_types=1);

namespace ipad54\BedrockEditionClient\network;

use ipad54\BedrockEditionClient\Client;
use ipad54\BedrockEditionClient\network\handler\PreSpawnPacketHandler;
use ipad54\BedrockEditionClient\network\raknet\RakNetConnection;
use ipad54\BedrockEditionClient\player\LoginInfo;
use ipad54\BedrockEditionClient\player\Player;
use ipad54\BedrockEditionClient\utils\KeyPair;
use pocketmine\network\mcpe\compression\Compressor;
use pocketmine\network\mcpe\compression\DecompressionException;
use pocketmine\network\mcpe\encryption\DecryptionException;
use pocketmine\network\mcpe\encryption\EncryptionContext;
use pocketmine\network\mcpe\encryption\EncryptionUtils;
use pocketmine\network\mcpe\handler\PacketHandler;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\protocol\BiomeDefinitionListPacket;
use pocketmine\network\mcpe\protocol\CameraAimAssistPresetsPacket;
use pocketmine\network\mcpe\protocol\ClientboundPacket;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\mcpe\protocol\Packet;
use pocketmine\network\mcpe\protocol\PacketDecodeException;
use pocketmine\network\mcpe\protocol\PacketPool;
use pocketmine\network\mcpe\protocol\ProtocolInfo;
use pocketmine\network\mcpe\protocol\serializer\PacketBatch;
use pocketmine\network\mcpe\protocol\serializer\PacketSerializer;
use pocketmine\network\mcpe\protocol\ServerboundPacket;
use pocketmine\network\mcpe\protocol\StartGamePacket;
use pocketmine\network\mcpe\protocol\types\CompressionAlgorithm;
use pocketmine\network\mcpe\protocol\types\login\JwtChain;
use pocketmine\network\PacketHandlingException;
use pocketmine\utils\BinaryDataException;
use pocketmine\utils\BinaryStream;
use raklib\utils\InternetAddress;
use function base64_decode;
use function base64_encode;
use function bin2hex;
use function chr;
use function get_class;
use function json_encode;
use function openssl_pkey_new;
use function ord;
use function random_bytes;
use function strlen;
use function substr;
use function time;

class NetworkSession{
	private const MTU = 1492;

	private InternetAddress $serverAddress;
	private LoginInfo $loginInfo;

	private Client $client;

	private RakNetConnection $connection;
	private ?Compressor $compressor = null;

	private ?EncryptionContext $cipher = null;

	private \Logger $logger;

	private PacketPool $packetPool;
	private ?PacketHandler $handler = null;

	private ClientPacketSender $sender;

	private ?Player $player = null;

	private KeyPair $keyPair;

	private bool $loggedIn = false;

	private int $protocol;

	public function __construct(InternetAddress $serverAddress, LoginInfo $loginInfo, Client $client){
		$this->serverAddress = $serverAddress;
		$this->loginInfo = $loginInfo;
		$this->client = $client;

		$this->logger = $client->getLogger();

		$this->packetPool = PacketPool::getInstance();
	}

	public function getServerAddress() : InternetAddress{
		return $this->serverAddress;
	}

	public function getClient() : Client{
		return $this->client;
	}

	public function getConnection() : RakNetConnection{
		return $this->connection;
	}

	public function getCompressor() : Compressor{
		return $this->compressor;
	}

	public function getPlayer() : ?Player{
		return $this->player;
	}

	public function getKeyPair() : KeyPair{
		return $this->keyPair;
	}

	public function getCipher() : ?EncryptionContext{
		return $this->cipher;
	}

	public function isLoggedIn() : bool{
		return $this->loggedIn;
	}

	public function getProtocol() : int{
		return $this->protocol;
	}

	public function setProtocol(int $protocol) : void{
		$this->protocol = $protocol;
	}

	public function update() : void{
		$this->connection->update();
	}

	public function actuallyConnect() : void{
		$this->connection = new RakNetConnection($this, $this->logger, self::MTU);
		$this->sender = new ClientPacketSender($this->connection);
		$this->handler = new PreSpawnPacketHandler($this);
	}

	public function getHandler() : ?PacketHandler{
		return $this->handler;
	}

	public function setHandler(?PacketHandler $handler) : void{
		$this->handler = $handler;

		if($this->handler !== null){
			$this->handler->setUp();
			$this->logger->debug("A new packet handler has been set (" . ($handler !== null ? get_class($handler) : "null") . ")");
		}
	}

	public function createPlayer(StartGamePacket $packet) : void{
		if($this->player !== null){
			throw new \LogicException("Player is already created!");
		}
		$this->player = new Player($this, $this->loginInfo, $packet, $this->client->getId());

		$this->logger->debug("Player was created, eid: " . $this->client->getId());
	}

	public function startEncryption(string $handshakeJwt) : void{
		if($this->cipher !== null){
			throw new \LogicException("Encryption is already started!");
		}

		[$header, $body] = JwtUtils::parse($handshakeJwt);

		$remotePub = JwtUtils::parseDerPublicKey(base64_decode($header["x5u"]));

		$this->keyPair->setRemotePub($remotePub);

		$sharedSecret = EncryptionUtils::generateSharedSecret($this->keyPair->getLocalPriv(), $remotePub);
		$encryptionKey = EncryptionUtils::generateKey($sharedSecret, base64_decode($body["salt"]));

		$this->cipher = EncryptionContext::fakeGCM($encryptionKey);

		$this->logger->debug("Encryption was started, key: " . bin2hex($encryptionKey));
	}

	public function handleEncoded(string $payload) : void{
		if($this->cipher !== null){
			try{
				$payload = $this->cipher->decrypt($payload);
			}catch(DecryptionException $e){
				$this->logger->debug("Encrypted packet: " . base64_encode($payload));
				throw PacketHandlingException::wrap($e, "Packet decryption error");
			}
		}

		if($payload === ""){
			throw new PacketHandlingException("No bytes in payload");
		}

		if($this->compressor !== null){
			if($this->protocol >= ProtocolInfo::PROTOCOL_1_20_60){
				$compressionType = ord($payload[0]);
				$compressed = substr($payload, 1);
				if($compressionType === CompressionAlgorithm::NONE){
					$decompressed = $compressed;
				}elseif($compressionType === $this->compressor->getNetworkId()){
					try{
						$decompressed = $this->compressor->decompress($compressed);
					}catch(DecompressionException $e){
						$this->logger->debug("Failed to decompress packet: " . base64_encode($compressed));
						throw PacketHandlingException::wrap($e, "Compressed packet batch decode error");
					}
				}else{
					throw new PacketHandlingException("Packet compressed with unexpected compression type $compressionType");
				}
			} else {
				try{
					$decompressed = $this->compressor->decompress($payload);
				}catch(DecompressionException $e){
					$this->logger->debug("Failed to decompress packet: " . base64_encode($payload));
					throw PacketHandlingException::wrap($e, "Compressed packet batch decode error");
				}
			}
		}else{
			$decompressed = $payload;
		}

		try{
			$stream = new BinaryStream($decompressed);
			foreach(PacketBatch::decodeRaw($stream) as $buffer){
				$packet = $this->packetPool->getPacket($buffer);
				if($packet === null){
					$this->logger->debug("Unknown packet: " . base64_encode($buffer));
					throw new PacketHandlingException("Unknown packet received");
				}
				try{
					$this->handleDataPacket($packet, $buffer);
				}catch(PacketHandlingException $e){
					$this->logger->debug($packet->getName() . ": " . base64_encode($buffer));
					throw PacketHandlingException::wrap($e, "Error processing " . $packet->getName());
				}
			}
		}catch(PacketDecodeException|BinaryDataException $e){
			$this->logger->logException($e);
			throw PacketHandlingException::wrap($e, "Packet batch decode error");
		}
	}

	public function handleDataPacket(Packet $packet, string $buffer) : void{
		if(!($packet instanceof ClientboundPacket)){
			throw new PacketHandlingException("Unexpected non-clientbound packet");
		}

		try{
			$packet->decode(PacketSerializer::decoder($this->protocol, $buffer, 0));
		}catch(\Throwable $e){
			$this->logger->logException($e);
			return;
		}

		if($this->handler !== null){
			$packet->handle($this->handler);
		}

		foreach($this->client->getDataPacketHandlers() as $handler){
			$handler($packet);
		}

	}

	public function sendDataPacket(ServerboundPacket $packet, bool $immediate = false) : void{
		$encoder = PacketSerializer::encoder($this->protocol);
		$packet->encode($encoder);
		$buffer = $encoder->getBuffer();

		$stream = new BinaryStream();
		PacketBatch::encodeRaw($stream, [$buffer]);
		$buffer = $stream->getBuffer();

		if($this->compressor !== null){
			if($this->protocol >= ProtocolInfo::PROTOCOL_1_20_60 && (($threshold = $this->compressor->getCompressionThreshold()) === null || strlen($buffer) < $threshold)){
				$compressionType = CompressionAlgorithm::NONE;
				$compressed = $buffer;
			}else{
				$compressionType = $this->compressor->getNetworkId();
				$compressed = $this->compressor->compress($buffer);
			}

			$buffer = ($this->protocol >= ProtocolInfo::PROTOCOL_1_20_60 ? chr($compressionType) : "") . $compressed;
		}
		$buffer = $this->cipher?->encrypt($buffer) ?? $buffer;

		$this->sender->send($buffer, $immediate, null);
	}

	public function processLogin() : void{
		if($this->loggedIn){
			throw new \LogicException("Client already loggedIn!");
		}

		[$authInfoJson, $clientDataJwt] = $this->buildLoginData();

		$this->sendDataPacket(LoginPacket::create($this->protocol, json_encode($authInfoJson), $clientDataJwt));

		$this->loggedIn = true;

		$this->logger->debug("LoginPacket was sent, nickname: " . $this->loginInfo->getUsername());
	}

	protected function buildLoginData() : array{
		$localPriv = openssl_pkey_new(["ec" => ["curve_name" => "secp384r1"]]);
		$localPub = JwtUtils::emitDerPublicKey($localPriv);

		$this->keyPair = new KeyPair($localPriv, $localPub);

		$localPub = base64_encode($localPub);

		$header = [
			"alg" => "ES384",
			"x5u" => $localPub
		];

		$authInfoJson = ["chain" => [JwtUtils::create($header, [
			"exp" => time() + 3600,
			"extraData" => [
				"XUID" => "", //TODO: Xbox auth
				"displayName" => $this->loginInfo->getUsername(),
				"identity" => $this->loginInfo->getUuid()->toString(),
			],
			"identityPublicKey" => $localPub,
			"nbf" => time() - 3600
		], $localPriv)]];

		$skin = $this->loginInfo->getSkin();

		$clientDataJwt = JwtUtils::create($header, [
			"AnimatedImageData" => [], //TODO: Hardcoded value
			"ArmSize" => "wide", //TODO: Hardcoded value
			"CapeData" => "", //TODO: Hardcoded value
			"CapeId" => "", //TODO: Hardcoded value
			"CapeImageHeight" => 0, //TODO: Hardcoded value
			"CapeImageWidth" => 0, //TODO: Hardcoded value
			"CapeOnClassicSkin" => false, //TODO: Hardcoded value
			"ClientRandomId" => $this->client->getId(),
			"CompatibleWithClientSideChunkGen" => false, //TODO: Hardcoded value
			"CurrentInputMode" => 2, //TODO: Hardcoded value
			"DefaultInputMode" => 1, //TODO: Hardcoded value
			"DeviceId" => $this->loginInfo->getDeviceId(),
			"DeviceModel" => $this->loginInfo->getDeviceModel(),
			"DeviceOS" => $this->loginInfo->getDeviceOS(),
			"GameVersion" => ProtocolInfo::MINECRAFT_VERSION_NETWORK,
			"GuiScale" => 0, //TODO: Hardcoded value
			"IsEditorMode" => false, //TODO: Hardcoded value
			"LanguageCode" => $this->loginInfo->getLocale(),
			"OverrideSkin" => true, //TODO: Hardcoded value
			"PersonaPieces" => [], //TODO: Hardcoded value
			"PersonaSkin" => false, //TODO: Hardcoded value
			"PieceTintColors" => [], //TODO: Hardcoded value
			"PlatformOfflineId" => "", //TODO: Hardcoded value
			"PlatformOnlineId" => "", //TODO: Hardcoded value
			"PlayFabId" => "f79a424e50f4736", //TODO: Hardcoded value
			"PremiumSkin" => false, //TODO: Hardcoded value
			"SelfSignedId" => base64_encode(random_bytes(16)),
			"ServerAddress" => $this->serverAddress->getIp() . ":" . $this->serverAddress->getPort(),
			"SkinAnimationData" => "", //TODO: Hardcoded value
			"SkinColor" => "#b37b62", //TODO: Hardcoded value
			"SkinData" => base64_encode($skin->getSkinData()),
			"SkinGeometryData" => "", //TODO: Hardcoded value
			"SkinGeometryDataEngineVersion" => "MS4xNC4w", //TODO: Hardcoded value
			"SkinId" => $skin->getSkinId(),
			"SkinImageHeight" => 64, //TODO: Hardcoded value
			"SkinImageWidth" => 64, //TODO: Hardcoded value
			"SkinResourcePatch" => base64_encode(json_encode(["geometry" => ["default" => "geometry.humanoid.custom"]])),
			"ThirdPartyName" => "", //TODO: Hardcoded value
			"ThirdPartyNameOnly" => false, //TODO: Hardcoded value
			"TrustedSkin" => true, //TODO: Hardcoded value
			"UIProfile" => 1 //TODO: Hardcoded value
		], $localPriv);

		if($this->protocol >= ProtocolInfo::PROTOCOL_1_21_90) {
			$authInfoJson = [
				"AuthenticationType" => 0,
				"Certificate" => json_encode($authInfoJson),
				"Token" => ""
			];
		}

		return [$authInfoJson, $clientDataJwt];
	}

	public function setCompressor(?Compressor $compressor) : NetworkSession{
		$this->compressor = $compressor;
		return $this;
	}
}
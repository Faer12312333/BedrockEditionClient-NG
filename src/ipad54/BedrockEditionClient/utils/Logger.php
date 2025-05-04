<?php
declare(strict_types=1);

namespace ipad54\BedrockEditionClient\utils;

use pocketmine\utils\Terminal;
use pocketmine\utils\TextFormat;
use pocketmine\utils\Utils;
use function implode;
use function sprintf;

class Logger implements \Logger{
	protected bool $logDebug;

	private string $format = TextFormat::AQUA . "[%s] " . TextFormat::RESET . "%s[%s]: %s" . TextFormat::RESET;

	private bool $useFormattingCodes;

	private string $timezone;

	public function __construct(bool $useFormattingCodes, \DateTimeZone $timezone, bool $logDebug = false){
		$this->logDebug = $logDebug;

		$this->useFormattingCodes = $useFormattingCodes;
		$this->timezone = $timezone->getName();
	}

	/**
	 * Returns the current logger format used for console output.
	 */
	public function getFormat() : string{
		return $this->format;
	}

	/**
	 * Sets the logger format to use for outputting text to the console.
	 * It should be an sprintf()able string accepting 5 string arguments:
	 * - time
	 * - color
	 * - thread name
	 * - prefix (debug, info etc)
	 * - message
	 *
	 * @see http://php.net/manual/en/function.sprintf.php
	 */
	public function setFormat(string $format) : void{
		$this->format = $format;
	}

	public function emergency($message) : void{
		$this->send($message, \LogLevel::EMERGENCY, "EMERGENCY", TextFormat::RED);
	}

	public function alert($message) : void{
		$this->send($message, \LogLevel::ALERT, "ALERT", TextFormat::RED);
	}

	public function critical($message) : void{
		$this->send($message, \LogLevel::CRITICAL, "CRITICAL", TextFormat::RED);
	}

	public function error($message) : void{
		$this->send($message, \LogLevel::ERROR, "ERROR", TextFormat::DARK_RED);
	}

	public function warning($message) : void{
		$this->send($message, \LogLevel::WARNING, "WARNING", TextFormat::YELLOW);
	}

	public function notice($message) : void{
		$this->send($message, \LogLevel::NOTICE, "NOTICE", TextFormat::AQUA);
	}

	public function info($message) : void{
		$this->send($message, \LogLevel::INFO, "INFO", TextFormat::WHITE);
	}

	public function debug($message, bool $force = false) : void{
		if(!$this->logDebug && !$force){
			return;
		}
		$this->send($message, \LogLevel::DEBUG, "DEBUG", TextFormat::GRAY);
	}

	public function setLogDebug(bool $logDebug) : void{
		$this->logDebug = $logDebug;
	}

	/**
	 * @param mixed[][]|null                          $trace
	 *
	 * @phpstan-param list<array<string, mixed>>|null $trace
	 *
	 * @return void
	 */
	public function logException(\Throwable $e, $trace = null) : void{
		$this->critical(implode("\n", Utils::printableExceptionInfo($e, $trace)));
	}

	public function log($level, $message) : void{
		switch($level){
			case \LogLevel::EMERGENCY:
				$this->emergency($message);
				break;
			case \LogLevel::ALERT:
				$this->alert($message);
				break;
			case \LogLevel::CRITICAL:
				$this->critical($message);
				break;
			case \LogLevel::ERROR:
				$this->error($message);
				break;
			case \LogLevel::WARNING:
				$this->warning($message);
				break;
			case \LogLevel::NOTICE:
				$this->notice($message);
				break;
			case \LogLevel::INFO:
				$this->info($message);
				break;
			case \LogLevel::DEBUG:
				$this->debug($message);
				break;
		}
	}

	/**
	 * @param string $message
	 * @param string $level
	 * @param string $prefix
	 * @param string $color
	 */
	protected function send(string $message, string $level, string $prefix, string $color) : void{
		$time = new \DateTime("now", new \DateTimeZone($this->timezone));

		$message = sprintf($this->format, $time->format("H:i:s.v"), $color, $prefix, TextFormat::clean($message, false));

		if(!Terminal::isInit()){
			Terminal::init($this->useFormattingCodes); //lazy-init colour codes because we don't know if they've been registered on this thread
		}
		Terminal::writeLine($message);
	}
}

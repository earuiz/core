<?php
/**
 * @author Björn Schießle <schiessle@owncloud.com>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 *
 * @copyright Copyright (c) 2015, ownCloud, Inc.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OC\Files\Storage\Wrapper;

use OC\Encryption\Exceptions\ModuleDoesNotExistsException;
use OC\Files\Storage\LocalTempFileTrait;
use OCP\Files\Mount\IMountPoint;

class Encryption extends Wrapper {

	use LocalTempFileTrait;

	/** @var string */
	private $mountPoint;

	/** @var \OC\Encryption\Util */
	private $util;

	/** @var \OC\Encryption\Manager */
	private $encryptionManager;

	/** @var \OC\Log */
	private $logger;

	/** @var string */
	private $uid;

	/** @var array */
	private $unencryptedSize;

	/** @var \OC\Encryption\File */
	private $fileHelper;

	/** @var IMountPoint */
	private $mount;

	/**
	 * @param array $parameters
	 * @param \OC\Encryption\Manager $encryptionManager
	 * @param \OC\Encryption\Util $util
	 * @param \OC\Log $logger
	 * @param \OC\Encryption\File $fileHelper
	 * @param string $uid user who perform the read/write operation (null for public access)
	 */
	public function __construct(
			$parameters,
			\OC\Encryption\Manager $encryptionManager = null,
			\OC\Encryption\Util $util = null,
			\OC\Log $logger = null,
			\OC\Encryption\File $fileHelper = null,
			$uid = null
		) {

		$this->mountPoint = $parameters['mountPoint'];
		$this->mount = $parameters['mount'];
		$this->encryptionManager = $encryptionManager;
		$this->util = $util;
		$this->logger = $logger;
		$this->uid = $uid;
		$this->fileHelper = $fileHelper;
		$this->unencryptedSize = array();
		parent::__construct($parameters);
	}

	/**
	 * see http://php.net/manual/en/function.filesize.php
	 * The result for filesize when called on a folder is required to be 0
	 *
	 * @param string $path
	 * @return int
	 */
	public function filesize($path) {
		$fullPath = $this->getFullPath($path);

		$info = $this->getCache()->get($path);
		if (isset($this->unencryptedSize[$fullPath])) {
			$size = $this->unencryptedSize[$fullPath];

			if (isset($info['fileid'])) {
				$info['encrypted'] = true;
				$info['size'] = $size;
				$this->getCache()->put($path, $info);
			}
			return $size;
		}

		if (isset($info['fileid']) && $info['encrypted']) {
			return $info['size'];
		}
		return $this->storage->filesize($path);
	}

	/**
	 * see http://php.net/manual/en/function.file_get_contents.php
	 *
	 * @param string $path
	 * @return string
	 */
	public function file_get_contents($path) {

		$encryptionModule = $this->getEncryptionModule($path);

		if ($encryptionModule) {
			$handle = $this->fopen($path, "r");
			if (!$handle) {
				return false;
			}
			$data = stream_get_contents($handle);
			fclose($handle);
			return $data;
		}
		return $this->storage->file_get_contents($path);
	}

	/**
	 * see http://php.net/manual/en/function.file_put_contents.php
	 *
	 * @param string $path
	 * @param string $data
	 * @return bool
	 */
	public function file_put_contents($path, $data) {
		// file put content will always be translated to a stream write
		$handle = $this->fopen($path, 'w');
		$written = fwrite($handle, $data);
		fclose($handle);
		return $written;
	}

	/**
	 * see http://php.net/manual/en/function.unlink.php
	 *
	 * @param string $path
	 * @return bool
	 */
	public function unlink($path) {
		$fullPath = $this->getFullPath($path);
		if ($this->util->isExcluded($fullPath)) {
			return $this->storage->unlink($path);
		}

		$encryptionModule = $this->getEncryptionModule($path);
		if ($encryptionModule) {
			$keyStorage = $this->getKeyStorage($encryptionModule->getId());
			$keyStorage->deleteAllFileKeys($this->getFullPath($path));
		}

		return $this->storage->unlink($path);
	}

	/**
	 * see http://php.net/manual/en/function.rename.php
	 *
	 * @param string $path1
	 * @param string $path2
	 * @return bool
	 */
	public function rename($path1, $path2) {
		$fullPath1 = $this->getFullPath($path1);
		if ($this->util->isExcluded($fullPath1)) {
			return $this->storage->rename($path1, $path2);
		}

		$source = $this->getFullPath($path1);
		$result = $this->storage->rename($path1, $path2);
		if ($result) {
			$target = $this->getFullPath($path2);
			if (isset($this->unencryptedSize[$source])) {
				$this->unencryptedSize[$target] = $this->unencryptedSize[$source];
			}
			$encryptionModule = $this->getEncryptionModule($path2);
			if ($encryptionModule) {
				$keyStorage = $this->getKeyStorage($encryptionModule->getId());
				$keyStorage->renameKeys($source, $target);
			}
		}

		return $result;
	}

	/**
	 * see http://php.net/manual/en/function.copy.php
	 *
	 * @param string $path1
	 * @param string $path2
	 * @return bool
	 */
	public function copy($path1, $path2) {
		$fullPath1 = $this->getFullPath($path1);
		if ($this->util->isExcluded($fullPath1)) {
			return $this->storage->copy($path1, $path2);
		}

		$source = $this->getFullPath($path1);
		$result = $this->storage->copy($path1, $path2);
		if ($result) {
			$target = $this->getFullPath($path2);
			$encryptionModule = $this->getEncryptionModule($path2);
			if ($encryptionModule) {
				$keyStorage = $this->getKeyStorage($encryptionModule->getId());
				$keyStorage->copyKeys($source, $target);
			}
		}

		return $result;
	}

	/**
	 * see http://php.net/manual/en/function.fopen.php
	 *
	 * @param string $path
	 * @param string $mode
	 * @return resource
	 */
	public function fopen($path, $mode) {

		$encryptionEnabled = $this->encryptionManager->isEnabled();
		$shouldEncrypt = false;
		$encryptionModule = null;
		$header = $this->getHeader($path);
		$fullPath = $this->getFullPath($path);
		$encryptionModuleId = $this->util->getEncryptionModuleId($header);

		$size = $unencryptedSize = 0;
		$targetExists = $this->file_exists($path);
		$targetIsEncrypted = false;
		if ($targetExists) {
			// in case the file exists we require the explicit module as
			// specified in the file header - otherwise we need to fail hard to
			// prevent data loss on client side
			if (!empty($encryptionModuleId)) {
				$targetIsEncrypted = true;
				$encryptionModule = $this->encryptionManager->getEncryptionModule($encryptionModuleId);
			}

			$size = $this->storage->filesize($path);
			$unencryptedSize = $this->filesize($path);
		}

		try {

			if (
				$mode === 'w'
				|| $mode === 'w+'
				|| $mode === 'wb'
				|| $mode === 'wb+'
			) {
				if (!empty($encryptionModuleId)) {
					$encryptionModule = $this->encryptionManager->getEncryptionModule($encryptionModuleId);
					$shouldEncrypt = $encryptionModule->shouldEncrypt($fullPath);
				} elseif ($encryptionEnabled) {
					$encryptionModule = $this->encryptionManager->getDefaultEncryptionModule();
					$shouldEncrypt = $encryptionModule->shouldEncrypt($fullPath);
				}
			} else {
				// only get encryption module if we found one in the header
				if (!empty($encryptionModuleId)) {
					$encryptionModule = $this->encryptionManager->getEncryptionModule($encryptionModuleId);
					$shouldEncrypt = true;
				}
			}
		} catch (ModuleDoesNotExistsException $e) {
			$this->logger->warning('Encryption module "' . $encryptionModuleId .
				'" not found, file will be stored unencrypted (' . $e->getMessage() . ')');
		}

		// encryption disabled on write of new file and write to existing unencrypted file -> don't encrypt
		if (!$encryptionEnabled || !$this->mount->getOption('encrypt', true)) {
			if (!$targetExists || !$targetIsEncrypted) {
				$shouldEncrypt = false;
			}
		}

		if($shouldEncrypt === true && !$this->util->isExcluded($fullPath) && $encryptionModule !== null) {
			$source = $this->storage->fopen($path, $mode);
			$handle = \OC\Files\Stream\Encryption::wrap($source, $path, $fullPath, $header,
				$this->uid, $encryptionModule, $this->storage, $this, $this->util, $this->fileHelper, $mode,
				$size, $unencryptedSize);
			return $handle;
		} else {
			return $this->storage->fopen($path, $mode);
		}
	}

	/**
	 * get the path to a local version of the file.
	 * The local version of the file can be temporary and doesn't have to be persistent across requests
	 *
	 * @param string $path
	 * @return string
	 */
	public function getLocalFile($path) {
		return $this->getCachedFile($path);
	}

	/**
	 * Returns the wrapped storage's value for isLocal()
	 *
	 * @return bool wrapped storage's isLocal() value
	 */
	public function isLocal() {
		return false;
	}

	/**
	 * see http://php.net/manual/en/function.stat.php
	 * only the following keys are required in the result: size and mtime
	 *
	 * @param string $path
	 * @return array
	 */
	public function stat($path) {
		$stat = $this->storage->stat($path);
		$fileSize = $this->filesize($path);
		$stat['size'] = $fileSize;
		$stat[7] = $fileSize;
		return $stat;
	}

	/**
	 * see http://php.net/manual/en/function.hash.php
	 *
	 * @param string $type
	 * @param string $path
	 * @param bool $raw
	 * @return string
	 */
	public function hash($type, $path, $raw = false) {
		$fh = $this->fopen($path, 'rb');
		$ctx = hash_init($type);
		hash_update_stream($ctx, $fh);
		fclose($fh);
		return hash_final($ctx, $raw);
	}

	/**
	 * return full path, including mount point
	 *
	 * @param string $path relative to mount point
	 * @return string full path including mount point
	 */
	protected function getFullPath($path) {
		return \OC\Files\Filesystem::normalizePath($this->mountPoint . '/' . $path);
	}

	/**
	 * read header from file
	 *
	 * @param string $path
	 * @return array
	 */
	protected function getHeader($path) {
		$header = '';
		if ($this->storage->file_exists($path)) {
			$handle = $this->storage->fopen($path, 'r');
			$header = fread($handle, $this->util->getHeaderSize());
			fclose($handle);
		}
		return $this->util->readHeader($header);
	}

	/**
	 * read encryption module needed to read/write the file located at $path
	 *
	 * @param string $path
	 * @return null|\OCP\Encryption\IEncryptionModule
	 * @throws ModuleDoesNotExistsException
	 * @throws \Exception
	 */
	protected function getEncryptionModule($path) {
		$encryptionModule = null;
		$header = $this->getHeader($path);
		$encryptionModuleId = $this->util->getEncryptionModuleId($header);
		if (!empty($encryptionModuleId)) {
			try {
				$encryptionModule = $this->encryptionManager->getEncryptionModule($encryptionModuleId);
			} catch (ModuleDoesNotExistsException $e) {
				$this->logger->critical('Encryption module defined in "' . $path . '" not loaded!');
				throw $e;
			}
		}
		return $encryptionModule;
	}

	public function updateUnencryptedSize($path, $unencryptedSize) {
		$this->unencryptedSize[$path] = $unencryptedSize;
	}

	/**
	 * @param string $encryptionModuleId
	 * @return \OCP\Encryption\Keys\IStorage
	 */
	protected function getKeyStorage($encryptionModuleId) {
		$keyStorage = \OC::$server->getEncryptionKeyStorage($encryptionModuleId);
		return $keyStorage;
	}

}

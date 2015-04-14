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

namespace OC\Encryption;

use OC\Files\Storage\Wrapper\Encryption;
use OCP\Encryption\IEncryptionModule;
use OCP\Files\Mount\IMountPoint;

class Manager implements \OCP\Encryption\IManager {

	/** @var array */
	protected $encryptionModules;

	/** @var \OCP\IConfig */
	protected $config;

	/**
	 * @param \OCP\IConfig $config
	 */
	public function __construct(\OCP\IConfig $config) {
		$this->encryptionModules = array();
		$this->config = $config;
	}

	/**
	 * Check if encryption is enabled
	 *
	 * @return bool true if enabled, false if not
	 */
	public function isEnabled() {

		$installed = $this->config->getSystemValue('installed', false);
		if (!$installed) {
			return false;
		}

		$enabled = $this->config->getAppValue('core', 'encryption_enabled', 'no');
		return $enabled === 'yes';
	}

	/**
	 * Registers an callback function which must return an encryption module instance
	 *
	 * @param callable $callback
	 * @throws Exceptions\ModuleAlreadyExistsException
	 */
	public function registerEncryptionModule(callable $callback) {
		$instance = call_user_func($callback);
		$id = $instance->getId();
		$name = $instance->getDisplayName();

		if (isset($this->encryptionModules[$id])) {
			throw new Exceptions\ModuleAlreadyExistsException($id, $name);
		}

		$defaultEncryptionModuleId = $this->getDefaultEncryptionModuleId();

		if (empty($defaultEncryptionModuleId)) {
			$this->setDefaultEncryptionModule($id);
		}

		$this->encryptionModules[$id] = $callback;
	}

	/**
	 * Unregisters an encryption module
	 *
	 * @param string $moduleId
	 */
	public function unregisterEncryptionModule($moduleId) {
		unset($this->encryptionModules[$moduleId]);
	}

	/**
	 * get a list of all encryption modules
	 *
	 * @return IEncryptionModule[]
	 */
	public function getEncryptionModules() {
		return $this->encryptionModules;
	}

	/**
	 * get a specific encryption module
	 *
	 * @param string $moduleId
	 * @return IEncryptionModule
	 * @throws Exceptions\ModuleDoesNotExistsException
	 */
	public function getEncryptionModule($moduleId = '') {
		if (!empty($moduleId)) {
			if (isset($this->encryptionModules[$moduleId])) {
				return call_user_func($this->encryptionModules[$moduleId]);
			} else {
				$message = "Module with id: $moduleId does not exists.";
				throw new Exceptions\ModuleDoesNotExistsException($message);
			}
		} else { // get default module and return this
				 // For now we simply return the first module until we have a way
	             // to enable multiple modules and define a default module
			$module = reset($this->encryptionModules);
			if ($module) {
				return call_user_func($module);
			} else {
				$message = 'No encryption module registered';
				throw new Exceptions\ModuleDoesNotExistsException($message);
			}
		}
	}

	/**
	 * get default encryption module
	 *
	 * @return \OCP\Encryption\IEncryptionModule
	 * @throws Exceptions\ModuleDoesNotExistsException
	 */
	public function getDefaultEncryptionModule() {
		$defaultModuleId = $this->getDefaultEncryptionModuleId();
		if (!empty($defaultModuleId)) {
			if (isset($this->encryptionModules[$defaultModuleId])) {
				return call_user_func($this->encryptionModules[$defaultModuleId]);
			} else {
				$message = 'Default encryption module not loaded';
				throw new Exceptions\ModuleDoesNotExistsException($message);
			}
		} else {
			$message = 'No default encryption module defined';
			throw new Exceptions\ModuleDoesNotExistsException($message);
		}

	}

	/**
	 * set default encryption module Id
	 *
	 * @param string $moduleId
	 * @return bool
	 */
	public function setDefaultEncryptionModule($moduleId) {
		try {
			$this->config->setAppValue('core', 'default_encryption_module', $moduleId);
			return true;
		} catch (\Exception $e) {
			return false;
		}

	}

	/**
	 * get default encryption module Id
	 *
	 * @return string
	 */
	protected function getDefaultEncryptionModuleId() {
		try {
			return $this->config->getAppValue('core', 'default_encryption_module');
		} catch (\Exception $e) {
			return '';
		}
	}

	public static function setupStorage() {
		\OC\Files\Filesystem::addStorageWrapper('oc_encryption', function ($mountPoint, $storage, IMountPoint $mount) {
			$parameters = [
				'storage' => $storage,
				'mountPoint' => $mountPoint,
				'mount' => $mount];

			if (!($storage instanceof \OC\Files\Storage\Shared)) {
				$manager = \OC::$server->getEncryptionManager();
				$util = new \OC\Encryption\Util(
					new \OC\Files\View(), \OC::$server->getUserManager(), \OC::$server->getConfig());
				$user = \OC::$server->getUserSession()->getUser();
				$logger = \OC::$server->getLogger();
				$uid = $user ? $user->getUID() : null;
				$fileHelper = \OC::$server->getEncryptionFilesHelper();
				return new Encryption($parameters, $manager, $util, $logger, $fileHelper, $uid);
			} else {
				return $storage;
			}
		}, 2);
	}
}

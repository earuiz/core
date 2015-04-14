<?php
/**
 * @author Björn Schießle <schiessle@owncloud.com>
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

namespace OCP\Encryption;

use OC\Encryption\Exceptions\ModuleDoesNotExistsException;
use OC\Encryption\Exceptions\ModuleAlreadyExistsException;

/**
 * This class provides access to files encryption apps.
 *
 */
interface IManager {

	/**
	 * Check if encryption is available (at least one encryption module needs to be enabled)
	 *
	 * @return bool true if enabled, false if not
	 */
	function isEnabled();

	/**
	 * Registers an callback function which must return an encryption module instance
	 *
	 * @param callable $callback
	 * @throws ModuleAlreadyExistsException
	 */
	function registerEncryptionModule(callable $callback);

	/**
	 * Unregisters an encryption module
	 *
	 * @param string $moduleId
	 */
	function unregisterEncryptionModule($moduleId);

	/**
	 * get a list of all encryption modules
	 *
	 * @return array
	 */
	function getEncryptionModules();


	/**
	 * get a specific encryption module
	 *
	 * @param string $moduleId
	 * @return IEncryptionModule
	 * @throws ModuleDoesNotExistsException
	 */
	function getEncryptionModule($moduleId);

	/**
	 * get default encryption module
	 *
	 * @return \OCP\Encryption\IEncryptionModule
	 * @throws ModuleDoesNotExistsException
	 */
	public function getDefaultEncryptionModule();

	/**
	 * set default encryption module Id
	 *
	 * @param string $moduleId
	 * @return string
	 */
	public function setDefaultEncryptionModule($moduleId);

}

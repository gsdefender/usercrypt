<?php
/**
 * UserCrypt - Sensitive joomla user information encryption
 * @package UserCrypt
 * @version @VERSION@
 * @revision @REVISION@
 * @license http://www.gnu.org/licenses/gpl-3.0.txt 	GNU General Public License v3
 * @copyright (C) @YEAR@ by Matej Koval - All rights reserved!
 * @website http://www.codegravity.com
 **/

 /** ensure this file is being included by a parent file */
defined( '_JEXEC' ) or die( 'Restricted access' );
	
if ( !file_exists( dirname(__FILE__) .DS. 'jcryptdatabase' .DS. 'jcryptdatabase_inherit.php' )) {
	JError::raiseNotice('no_jf_plugin', JText::_('Database plugin not installed correctly. Plugin not executed.'));
	return;
}

jimport('joomla.filesystem.file');
jimport('joomla.plugin.plugin');

/**
* Exchange of the database abstraction layer for multi lingual translations.
*/
class plgSystemJCryptDatabase extends JPlugin{
	/**
	 * stored configuration from plugin
	 *
	 * @var object configuration information
	 */
	var $_config = null;

	function plgSystemJCryptDatabase(& $subject, $config)
	{		
		parent::__construct($subject, $config);

		// put params in registry so I have easy access to them later
		$conf = JFactory::getConfig();
	}

	/**
	 * During this event we setup the database and link it to the Joomla! ressources for future use
	 * @return void
	 */
	function onAfterInitialise()
	{
		// load plugin params info
		$plugin			=& JPluginHelper::getPlugin('user', 'jcrypt');
		$pluginParams	= new JParameter($plugin->params);
		
		// set security key file content
		if($pluginParams->get('security_key') != NULL && $pluginParams->get('security_key') != '') {
			$security_key = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $pluginParams->get('security_key'));
		}
		
		if($security_key != NULL && $security_key != '') { // update all the data to encrypted state
			// change the column data types
			$db = & JFactory::getDBO();
			$db->setQuery('describe #__users');
			$db->query();
			$results = $db->loadObjectList();
			$flag = false; // for converting data
			
			foreach($results as $result) {
				if($result->Field == 'name' && strpos(strtolower($result->Type), 'varbinary') === false) {
					$db->setQuery('alter table #__users modify name varbinary(255) not null');
					$db->query();
					
					$flag = true;
				}
				
				if($result->Field == 'email' && strpos(strtolower($result->Type), 'varbinary') === false) {
					$db->setQuery('alter table #__users modify email varbinary(100) not null');
					$db->query();
					
					$flag = true;
				}
				
				if($result->Field == 'username' && strpos(strtolower($result->Type), 'varbinary') === false) {
					$db->setQuery('alter table #__users modify username varbinary(150) not null');
					$db->query();
					
					$flag = true;
				}
			}
			
			// that means this is the first time the plugin runs
			if($flag) {
				$db->setQuery("update #__users set name=AES_ENCRYPT(name, '" . $security_key . "'), username=AES_ENCRYPT(username, '" . $security_key . "'), email=AES_ENCRYPT(email, '" . $security_key . "')");
				$db->query();
			}
			//============================================================================================
		}
		
		$this->_setupJCryptDatabase(); // load new interceptor class
	}
	
	function _setupJCryptDatabase()
	{
		if (file_exists( dirname(__FILE__).DS.'jcryptdatabase'.DS.'jcryptdatabase_inherit.php' )) {
			require_once( dirname(__FILE__).DS.'jcryptdatabase'.DS.'jcryptdatabase_inherit.php' );
			
			$conf = JFactory::getConfig();

			$host 		= $conf->getValue('config.host');
			$user 		= $conf->getValue('config.user');
			$password 	= $conf->getValue('config.password');
			$db   		= $conf->getValue('config.db');
			$dbprefix 	= $conf->getValue('config.dbprefix');
			$dbtype 	= $conf->getValue('config.dbtype');
			$debug 		= $conf->getValue('config.debug');
			$driver 	= $conf->getValue('config.dbtype');

			$options = array("driver"=>$driver, "host"=>$host, "user"=>$user, "password"=>$password, "database"=>$db, "prefix"=>$dbprefix,"select"=>true);

			$db = & JFactory::getDBO();
			$db = new JCryptDatabase($options);
			$debug = $conf->getValue('config.debug');
			$db->debug($debug);

			if ($db->getErrorNum() > 2) {
				JError::raiseError('joomla.library:'.$db->getErrorNum(), 'JDatabase::getInstance: Could not connect to database <br/>' . $db->getErrorMsg() );
			}
		}
	}
}

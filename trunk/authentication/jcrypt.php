<?php
// Check to ensure this file is included in Joomla!
defined( '_JEXEC' ) or die( 'Restricted access' );

jimport( 'joomla.plugin.plugin' );

/**
 * Example Authentication Plugin
 *
 * @package		Joomla
 * @subpackage	JFramework
 * @since 1.5
 */
class plgAuthenticationJcrypt extends JPlugin
{
	private $_security_key = NULL;
	
	private $_db = NULL;
	
	/**
	 * Constructor
	 *
	 * For php4 compatability we must not use the __constructor as a constructor for plugins
	 * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
	 * This causes problems with cross-referencing necessary for the observer design pattern.
	 *
	 * @param	object	$subject	The object to observe
	 * @param	array	$config		An array that holds the plugin configuration
	 * @since	1.5
	 */
	function plgAuthenticationJcrypt(& $subject, $config)
	{
		// load plugin params info
		$plugin			=& JPluginHelper::getPlugin('user', 'jcrypt');
		$pluginParams	= new JParameter($plugin->params);
		
		// set security key file content
		if($pluginParams->get('security_key') != NULL && $pluginParams->get('security_key') != '') {
			$this->_security_key = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $pluginParams->get('security_key'));
		}
		
		// set db object
		$this->_db =& JFactory::getDBO();
		
		parent::__construct($subject, $config);
	}

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @access	public
	 * @param	array	$credentials	Array holding the user credentials
	 * @param	array	$options		Array of extra options
	 * @param	object	$response		Authentication response object
	 * @return	boolean
	 * @since	1.5
	 */
	function onAuthenticate( $credentials, $options, &$response )
	{
		/*
		 * Here you would do whatever you need for an authentication routine with the credentials
		 *
		 * In this example the mixed variable $return would be set to false
		 * if the authentication routine fails or an integer userid of the authenticated
		 * user if the routine passes
		 */
		if($this->_security_key != NULL && $this->_security_key != '') {
			jimport('joomla.user.helper');
	
			$response->type = 'Jcrypt';
			
			// Joomla does not like blank passwords
			if (empty($credentials['password'])) {
				$response->status = JAUTHENTICATE_STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
				return false;
			}

			// Initialise variables.
			$conditions = '';
	
			// Set the database query to get user information with encrypted username 
			$query	= "SELECT id, password FROM #__users WHERE username='" . $credentials['username'] . "'";
			$this->_db->setQuery($query);
			$result = $this->_db->loadObject();
			//========================================================================//
		
			if ($result) {
				$parts	= explode(':', $result->password);
				$crypt	= $parts[0];
				$salt	= @$parts[1];
				$testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt);
	
				if ($crypt == $testcrypt) {
					$user = JUser::getInstance($result->id); // Bring this in line with the rest of the system
					
					// set actual user information in user instance
					$query	= "SELECT name AS enc_fullname, AES_DECRYPT(name, '" . $this->_security_key . "') AS name, username AS enc_username, AES_DECRYPT(username, '" . $this->_security_key . "') AS username, email AS enc_email, AES_DECRYPT(email, '" . $this->_security_key . "') AS email FROM #__users WHERE id=" . $user->id;
					$this->_db->setQuery($query);
					$enc_user = $this->_db->loadObject();
					
					$user->name = $enc_user->name;
					$user->username = $enc_user->username;
					$user->email = $enc_user->email;
					
					$user->enc_fullname = $enc_user->enc_fullname;
					$user->enc_username = $enc_user->enc_username;
					$user->enc_email = $enc_user->enc_email;
					//===================================================//
					
					$response->username = $user->username;
					$response->email = $user->email;
					$response->fullname = $user->name;
					
					if (JFactory::getApplication()->isAdmin()) {
						$response->language = $user->getParam('admin_language');
					}
					else {
						$response->language = $user->getParam('language');
					}
					$response->status = JAUTHENTICATE_STATUS_SUCCESS;
					$response->error_message = '';
					//return true;
				} else {
					$response->status = JAUTHENTICATE_STATUS_FAILURE;
					$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
					//return false;
				}
			} else {
				$response->status = JAUTHENTICATE_STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
				//return false;
			}
		}
	}
}

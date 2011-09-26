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

 // Check to ensure this file is included in Joomla!
defined('_JEXEC') or die( 'Restricted access' );

jimport('joomla.plugin.plugin');

/**
 * Example User Plugin
 *
 * @package		Joomla
 * @subpackage	JFramework
 * @since 		1.5
 */
class plgUserJcrypt extends JPlugin {

	private $_security_key = NULL;
	
	private $_db = NULL;
	
	/**
	 * Constructor
	 *
	 * For php4 compatability we must not use the __constructor as a constructor for plugins
	 * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
	 * This causes problems with cross-referencing necessary for the observer design pattern.
	 *
	 * @param object $subject The object to observe
	 * @param 	array  $config  An array that holds the plugin configuration
	 * @since 1.5
	 */
	function plgUserJcrypt(& $subject, $config)
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
	 * Example store user method
	 *
	 * Method is called before user data is stored in the database
	 *
	 * @param 	array		holds the old user data
	 * @param 	boolean		true if a new user is stored
	 */
	function onBeforeStoreUser($user, $isnew)
	{
		global $mainframe;
	}

	/**
	 * Example store user method
	 *
	 * Method is called after user data is stored in the database
	 *
	 * @param 	array		holds the new user data
	 * @param 	boolean		true if a new user is stored
	 * @param	boolean		true if user was succesfully stored in the database
	 * @param	string		message
	 */
	function onAfterStoreUser($user, $isnew, $success, $msg)
	{
		global $mainframe;

		// convert the user parameters passed to the event
		// to a format the external application

		$args = array();
		
		if($this->_security_key != NULL && $this->_security_key != '') {
			$sql = "UPDATE #__users SET name=AES_ENCRYPT('" . $user['name'] . "', '" . $this->_security_key . "'), username=AES_ENCRYPT('" . $user['username'] . "', '" . $this->_security_key . "'), email=AES_ENCRYPT('" . $user['email'] . "', '" . $this->_security_key . "') WHERE id=" . $user['id'];
			$this->_db->setQuery($sql);
			$this->_db->query();
			
			$sql = "SELECT * FROM #__core_acl_aro WHERE value=" . $user['id'];
			$this->_db->setQuery($sql);
			$this->_db->query();
			$result = $this->_db->loadObject();
			
			if(!$result) {
				$sql = "INSERT INTO #__core_acl_aro (section_value, value, order_value, name, hidden) VALUES ('users', " . $user['id'] . ", 0, '" . $user['username'] . "', 0)";
				$this->_db->setQuery($sql);
				$this->_db->query();
				
				$sql = "SELECT * FROM #__core_acl_aro WHERE value=" . $user['id'];
				$this->_db->setQuery($sql);
				$this->_db->query();
				$result1 = $this->_db->loadObject();
				
				if($result1) {
					$sql = "INSERT INTO #__core_acl_groups_aro_map (group_id, section_value, aro_id) VALUES (18, '', " . $result1->id . ")";
					$this->_db->setQuery($sql);
					$this->_db->query();
				}
			}
		}
		
		$args['username']	= $user['username'];
		$args['email'] 		= $user['email'];
		$args['fullname']	= $user['name'];
		$args['password']	= $user['password'];
		
		if ($isnew)
		{
			// Call a function in the external app to create the user
			// ThirdPartyApp::createUser($user['id'], $args);
		}
		else
		{
			// Call a function in the external app to update the user
			// ThirdPartyApp::updateUser($user['id'], $args);
		}
	}

	/**
	 * Example store user method
	 *
	 * Method is called before user data is deleted from the database
	 *
	 * @param 	array		holds the user data
	 */
	function onBeforeDeleteUser($user)
	{
		global $mainframe;
	}
	
	/**
	 * This method should handle any login logic and report back to the subject
	 *
	 * @access	public
	 * @param 	array 	holds the user data
	 * @param 	array    extra options
	 * @return	boolean	True on success
	 * @since	1.5
	 */
	function onLoginUser($user, $options = array())
	{
		if($this->_security_key != NULL && $this->_security_key != '') {
			jimport('joomla.user.helper');
	
			$instance = JUser::getInstance();
			if ($id = JUserHelper::getUserId($user['enc_username']))  {
				$instance->load($id);
			} else {
				$query	= "SELECT id FROM #__users WHERE username='" . $user['username'] . "'";
				$this->_db->setQuery($query);
				$result = $this->_db->loadObject();
				
				if($result) {
					$instance->load($result->id);
				}
			}
			//==============================================================
	
			// if _getUser returned an error, then pass it back.
			if (JError::isError( $instance )) {
				return $instance;
			}
	
			// If the user is blocked, redirect with an error
			if ($instance->get('block') == 1) {
				return JError::raiseWarning('SOME_ERROR_CODE', JText::_('E_NOLOGIN_BLOCKED'));
			}
	
			// Get an ACL object
			$acl =& JFactory::getACL();
	
			// Get the user group from the ACL
			if ($instance->get('tmp_user') == 1) {
				$grp = new JObject;
				// This should be configurable at some point
				$grp->set('name', 'Registered');
			} else {
				$grp = $acl->getAroGroup($instance->get('id'));
			}
	
			//Authorise the user based on the group information
			if(!isset($options['group'])) {
				$options['group'] = 'USERS';
			}
	
			//Mark the user as logged in
			$instance->set( 'guest', 0);
			$instance->set('aid', 1);
	
			// Fudge Authors, Editors, Publishers and Super Administrators into the special access group
			if ($acl->is_group_child_of($grp->name, 'Registered')      ||
				$acl->is_group_child_of($grp->name, 'Public Backend'))    {
				$instance->set('aid', 2);
			}
	
			//Set the usertype based on the ACL group name
			$instance->set('usertype', $grp->name);
	
			// Register the needed session variables
			$session =& JFactory::getSession();
			$session->set('user', $instance);
	
			// Get the session object
			$table = & JTable::getInstance('session');
			$table->load( $session->getId() );
	
			$table->guest 		= $instance->get('guest');
			$table->username 	= $instance->get('username');
			$table->userid 		= intval($instance->get('id'));
			$table->usertype 	= $instance->get('usertype');
			$table->gid 		= intval($instance->get('gid'));
	
			$table->update();
	
			// Hit the user last visit field
			$instance->setLastVisit();
		}
		
		return true;
	}

	/**
	 * This method should handle any logout logic and report back to the subject
	 *
	 * @access public
	 * @param array holds the user data
	 * @return boolean True on success
	 * @since 1.5
	 */
	function onLogoutUser($user, $options = array())
	{
		$my =& JFactory::getUser();
		
		//Make sure we're a valid user first
		if($user['id'] == 0 && !$my->get('tmp_user')) return true;

		//Check to see if we're deleting the current session
		if($my->get('id') == $user['id'])
		{
			// Hit the user last visit field
			$my->setLastVisit();

			// Destroy the php session for this user
			$session =& JFactory::getSession();
			$session->destroy();
		} else {
			// Force logout all users with that userid
			$table = & JTable::getInstance('session');
			$table->destroy($user['id'], $options['clientid']);
		}
		return true;
	}
	
	function onAfterDeleteUser($user, $succes, $msg)
	{
		if(!$succes) {
			return false;
		}

		$db =& JFactory::getDBO();
		$db->setQuery('DELETE FROM #__session WHERE userid = '.$db->Quote($user['id']));
		$db->Query();

		return true;
	}
}

<?php
// Don't allow direct linking
defined( '_JEXEC' ) or die( 'Direct Access to this location is not allowed.' );

include_once(dirname(__FILE__)."/intercept.".strtolower(get_class(JFactory::getDBO())).".php");

jimport('joomla.plugin.plugin');

class JCryptDatabase extends interceptDB {
	
	/** Constructor
	*/
	function JCryptDatabase($options) {
		parent::__construct($options);
	}
	
	/**
	* This global function loads the first row of a query into an object
	*/
	function loadObject() {
		$objects = $this->loadObjectList();
		if (!is_null($objects) && count($objects)>0){
			return $objects[0];
		}
		return null;
	}
	
	function setQuery($query, $offset = 0, $limit = 0)
	{
		// load plugin params info
		$plugin			=& JPluginHelper::getPlugin('user', 'jcrypt');
		$pluginParams	= new JParameter($plugin->params);
		
		// set security key file content
		if($pluginParams->get('security_key') != NULL && $pluginParams->get('security_key') != '') {
			$salt = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $pluginParams->get('security_key'));
		}
		
		// create new query with encrypt/decrypt fields
		if($salt != NULL && $salt != '') {
			$new_query = $this->replace_encrypted_fields($query, $salt);
		} else {
			$new_query = $query;
		}			
		
		// write query log in file
		/*$file = fopen($_SERVER['DOCUMENT_ROOT'] . 'joomla15/queries.txt', 'a+');
		fwrite($file, $query . '\n' . $new_query . '\r\n');
		fclose($file);*/
		
		parent::setQuery($new_query, $offset, $limit);
	}
	
	/**
	* Load a list of database objects
	* @param string The field name of a primary key
	* @return array If <var>key</var> is empty as sequential list of returned TRANSLATED records.
	* If <var>key</var> is not empty then the returned array is indexed by the value
	* the database key.  Returns <var>null</var> if the query fails.
	*/
	function loadObjectList($key='') {

		$result = parent::loadObjectList( $key );
		
		return $result;
	}
	
	function replace_encrypted_fields($query = NULL, $salt = NULL) {
		if(!is_null($query)) {
			if(strpos(strtolower($query), '#__users') !== false) {
				// remove the double space
				$query = str_replace('  ',' ', $query);
				
				// except insert, update delete query and queries that already have aes_encrypt/aes_decrypt method in it
				if (strpos(strtolower($query), 'insert into') === false && 
					strpos(strtolower($query), 'update') === false && 
					strpos(strtolower($query), 'delete from') === false && 
					strpos(strtolower($query), 'aes_encrypt') === false && 
					strpos(strtolower($query), 'aes_decrypt') === false
					) {
					
					// make the query lowercase
					$query = strtolower($query);
					
					// replace the cases where possible conflict may occur
					$query = str_replace(',',', ', $query);
					$query = str_replace(array('`', '  ', ' = ', '(', ')'), array('', ' ', '=', '( ', ' )'), $query);
					
					// explode the query parts with space
					$query_parts = explode(' ', $query);
					
					// if has any alias
					if(strpos($query, '#__users as') !== false) {					
						for($i = 0; $i < count($query_parts); $i++) {
							if(strpos($query_parts[$i], '_users') !== false) {
								$alias = $query_parts[$i + 2] . '.';
								break;
							}
						}
					} else {
						$alias = '';
					}
					
					for($i = 0; $i < count($query_parts); $i++) {
						// until the from position
						if($query_parts[$i] != 'from') {
							// if select name
							if(strpos($query_parts[$i], $alias . 'name') !== false) {
								$query_parts[$i] = "AES_DECRYPT(" . $alias . "name, '" . $salt . "')" . ($query_parts[$i + 1] != 'as' ? " AS name" : '');
							}
							
							// if select username
							if(strpos($query_parts[$i], $alias . 'username') !== false) {
								$query_parts[$i] = "AES_DECRYPT(" . $alias . "username, '" . $salt . "')" . ($query_parts[$i + 1] != 'as' ? " AS username" : '');
							}
							
							// if select email
							if(strpos($query_parts[$i], $alias . 'email') !== false) {
								$query_parts[$i] = "AES_DECRYPT(" . $alias . "email, '" . $salt . "')" . ($query_parts[$i + 1] != 'as' ? " AS email" : '');
							}
							
							// if select *
							if(strpos($query_parts[$i], $alias . '*') !== false) {
								$query_parts[$i] = $alias . "id, ";
								$query_parts[$i] .= "AES_DECRYPT(" . $alias . "name, '" . $salt . "') AS name, ";
								$query_parts[$i] .= "AES_DECRYPT(" . $alias . "username, '" . $salt . "') AS username, ";
								$query_parts[$i] .= "AES_DECRYPT(" . $alias . "email, '" . $salt . "') AS email, ";
								$query_parts[$i] .= $alias . "password, " . $alias . "usertype, " . $alias . "block, " . $alias . "sendEmail, " . $alias . "gid, " . $alias . "registerDate, " . $alias . "lastvisitDate, " . $alias . "activation, " . $alias . "params ";
								
								// if not from at last, then some other field, so need ","
								if($query_parts[$i + 1] != 'from') {
									$query_parts[$i] .= ', ';
								}
							}
						} else {
							break;
						}
					}
					
					// get the where position
					$j = 0;
					for($i = 0; $i < count($query_parts); $i++) {
						if($query_parts[$i] == 'where') {
							$j = $i;
							break;
						}
					}
					
					// set the encrypted field for where clause
					for($i = $j + 1; $i < count($query_parts); $i++) {
						if(strpos($query_parts[$i], $alias . 'username=') !== false) { // username field
							$part = substr($query_parts[$i], strlen($alias . 'username='), strlen($query_parts[$i]));
							$query_parts[$i] = $alias . "username=AES_ENCRYPT(" . $part . ", '" . $salt . "')";
						}
						
						if(strpos($query_parts[$i], $alias . 'username') !== false && $query_parts[$i + 1] == 'like') { // username field with like condition
							$part = str_replace(array("'", "%"), array("", ""), $query_parts[$i + 2]);
							$query_parts[$i + 2] = "AES_ENCRYPT('" . $part . "', '" . $salt . "')";
						}
						
						if(strpos($query_parts[$i], 'email=') !== false) { // email field
							$part = substr($query_parts[$i], strlen('email='), strlen($query_parts[$i]));
							$query_parts[$i] = "email=AES_ENCRYPT(" . $part . ", '" . $salt . "')";
						}
						
						if(strpos($query_parts[$i], $alias . 'email') !== false && $query_parts[$i + 1] == 'like') { // email field with like condition
							$part = str_replace(array("'", "%"), array("", ""), $query_parts[$i + 2]);
							$query_parts[$i + 2] = "AES_ENCRYPT('" . $part . "', '" . $salt . "')";
						}
						
						/*if(strpos($query_parts[$i], 'name=') !== false) { // name field conflicting with name in username
							$part = substr($query_parts[$i], strlen('name='), strlen($query_parts[$i]));
							$query_parts[$i] = "name=AES_ENCRYPT(" . $part . ", '" . $salt . "')";
						}*/
						
						if($query_parts[$i] == $alias . 'name' && $query_parts[$i + 1] == 'like') { // name field with like condition
							$part = str_replace(array("'", "%"), array("", ""), $query_parts[$i + 2]);
							$query_parts[$i + 2] = "AES_ENCRYPT('" . $part . "', '" . $salt . "')";
						}
					}
					
					// glue the modified query parts
					$query = '';
					
					for($i = 0; $i < count($query_parts); $i++) {
						$query .= $query_parts[$i] . ' ';
					}
				}	
			}
		}
		
		return $query;
	}
	
	/**
	 * Returns a reference to the global Database object, only creating it
	 * if it doesn't already exist. And keeps sure that there is only one
	 * instace for a specific combination of the JDatabase signature
	 *
	 * @param string  Database driver
	 * @param string Database host
	 * @param string Database user name
	 * @param string Database user password
	 * @param string Database name
	 * @param string Common prefix for all tables
	 * @return database A database object
	 * @since 1.5
	*/
	function &getInstance( $driver='mysql', $host='localhost', $user, $pass, $db='', $table_prefix='' )
	{
		$signature = serialize(array($driver, $host, $user, $pass, $db, $table_prefix));
		$database = JDatabase::_getStaticInstance($signature,'JCryptDatabase',true);

		return $database;
	}
}
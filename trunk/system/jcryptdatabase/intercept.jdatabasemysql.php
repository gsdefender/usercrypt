<?php
// Don't allow direct linking
defined( '_JEXEC' ) or die( 'Direct Access to this location is not allowed.' );

class interceptDB extends JDatabaseMySQL {

	/**
	 * This special constructor reuses the existing resource from the existing db connecton
	 *
	 * @param unknown_type $options
	 */
	function __construct($options){
		$db =  JFactory::getDBO();
		
		// support for recovery of existing connections
		if (isset($this->_options)) $this->_options = $options;

		$select		= array_key_exists('select', $options)	? $options['select']	: true;
		$database	= array_key_exists('database',$options)	? $options['database']	: '';

		// perform a number of fatality checks, then return gracefully
		if (!function_exists( 'mysql_connect' )) {
			$this->_errorNum = 1;
			$this->_errorMsg = 'The MySQL adapter "mysql" is not available.';
			return;
		}

		// connect to the server
		$this->_resource =  $db->_resource;

		// finalize initialization
		JDatabase::__construct($options);

		// select the database
		if ( $select ) {
			$this->select($database);
		}
	}	
}
?>

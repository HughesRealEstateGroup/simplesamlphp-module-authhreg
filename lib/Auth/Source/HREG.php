<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
$dir =  implode('/', array_slice( explode('/',__dir__),0,4));
require_once($dir.'/helpers.php');
class sspmod_authhreg_Auth_Source_HREG extends SimpleSAML_Auth_Source {


	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'hreg:init';


	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'hreg:AuthId';

	/**
	 * Log-in using HREG platform
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		/* We are going to need the authId in order to retrieve this authentication source later. */
		$state[self::AUTHID] = $this->authId;
		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);

		$linkback = SimpleSAML_Module::getModuleURL('authhreg/linkback.php', array('AuthState' => $stateID));
		SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);
		$ss = new SamlState();
		$ss->setState(strtok($stateID,':'));
		$ss->setRedirect($linkback);
		$ss->save();
		SimpleSAML_Utilities::redirectTrustedURL(getSiteRoot().'sso/simplesaml/'.strtok($stateID,':').'/');
	}
		

	public function finalStep(&$state) {
		assert('is_array($state)');
		$ss = SamlStateQuery::create()->findOneByState(strtok($state['SimpleSAML_Auth_State.id'],':'));
		if (!isset($ss)||$ss->getUser()==null) {
			throw new SimpleSAML_Error_AuthSource($this->authId, 'Error getting user profile.');
		}
		$user = $ss->getUser();
		$attributes = array();
		$attributes['uid']=array($user->getEmail());
		SimpleSAML_Logger::debug('HREG Returned Attributes: '. implode(", ", array_keys($attributes)));

		$state['Attributes'] = $attributes;
	}

}

?>
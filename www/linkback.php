<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);
/**
 * Handle linkback() response from Facebook.
 */
 
if (!array_key_exists('AuthState', $_REQUEST) || empty($_REQUEST['AuthState'])) {
	throw new SimpleSAML_Error_BadRequest('Missing state parameter on hreg linkback endpoint.');
}

$stateID = $_REQUEST['AuthState'];

// sanitize the input
$sid = SimpleSAML_Utilities::parseStateID($stateID);
if (!is_null($sid['url'])) {
	SimpleSAML_Utilities::checkURLAllowed($sid['url']);
}

$state = SimpleSAML_Auth_State::loadState($stateID, sspmod_authhreg_Auth_Source_HREG::STAGE_INIT);

/* Find authentication source. */
if (!array_key_exists(sspmod_authhreg_Auth_Source_HREG::AUTHID, $state)) {
	throw new SimpleSAML_Error_BadRequest('No data in state for ' . sspmod_authhreg_Auth_Source_HREG::AUTHID);
}
$sourceId = $state[sspmod_authhreg_Auth_Source_HREG::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new SimpleSAML_Error_BadRequest('Could not find authentication source with id ' . var_export($sourceId, TRUE));
}

try {
	if (isset($_REQUEST['error_reason']) && $_REQUEST['error_reason'] == 'user_denied') {
		throw new SimpleSAML_Error_UserAborted();
	}

	$source->finalStep($state);
} catch (SimpleSAML_Error_Exception $e) {
	SimpleSAML_Auth_State::throwException($state, $e);
} catch (Exception $e) {
	SimpleSAML_Auth_State::throwException($state, new SimpleSAML_Error_AuthSource($sourceId, 'Error on HREG linkback endpoint.', $e));
}
SimpleSAML_Auth_Source::completeAuth($state);

?>

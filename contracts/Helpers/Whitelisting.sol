pragma solidity ^0.5.4;

import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";


contract Whitelisting is Ownable {
    
    address public manager;
    
    mapping (address => bool) public whiteList;
    
    /*
    * @dev Contract Constructor
    *
    * @param _manager address of contract admin with whitelist rights
    */
    constructor(address _manager) public {
        manager = _manager;
    }
    
    /*
    * modifiers
    */
    modifier onlyManager {
        require(msg.sender == manager);
        _;
    }
    
    
    function setManager(address _newManager) public onlyOwner {
        require(_newManager != address(0));
        manager = _newManager;
    }
    
    /*
    * @dev function setWhitelisted sets the whitelist status of an address
    *
    * @param _whiteListedUser address the address of the user
    * @param isWhitelisted bool Status of the user
    */
    function setWhitelisted(address _whiteListedUser, bool isWhitelisted) public onlyManager {
        _setWhitelisted(_whiteListedUser, isWhitelisted);
    }
    
    /*
    * @dev function confirmedByManager performs a check if the user is whitelisted
    *
    * @param signature bytes is signed keccak256 of the user we are whitelisting
    */
    function confirmedByManager(bytes memory signature) internal view returns (bool) {
        bytes32 bytes32Message = keccak256(abi.encodePacked(msg.sender));
        bytes32 EthSignedMessageHash = ECDSA.toEthSignedMessageHash(bytes32Message);
        
        address signer = ECDSA.recover(EthSignedMessageHash, signature);
        
        return signer == manager;
    }
    
    /*
    * @dev function setWhitelisted sets the whitelist status of an address
    *
    * @param _whiteListedUser address the address of the user
    * @param isWhitelisted bool Status of the user
    */
    function _setWhitelisted(address _whiteListedUser, bool isWhitelisted) internal {
        require(_whiteListedUser != address(0));
        whiteList[_whiteListedUser] = isWhitelisted;
    }
}

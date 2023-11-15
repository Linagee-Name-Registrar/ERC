---
eip: 6###
title: ERC-#### Linagee Name Registrar and Ethereum Content Delivery Network
description: Introduces a new standard that delineates on-chain permanent domains and outlines their utilization for address mapping and decentralized content delivery networks (CDNs).
author: Mason Keresty (@m_keresty)
discussions-to: 
status: Draft
type: Standards Track
category: ERC
created: 2023-11-14
requires: 4804,  6860
---

## Abstract

Introduces a new standard that delineates on-chain permanent domains and outlines their utilization for address mapping and decentralized content delivery networks (CDNs) for [ERC-4804](./eip-4804.md).

## Motivation

ERC-4804 defines a `web3://`-scheme RFC 2396 URI to call a smart contract either by its address or a **name** from name service.  If a **name** is specified, the standard specifies a way to resolve the contract address from the name. This EIP expands ERC-4804 to include the Linagee Name Registrar (LNR) service and its use for permanent asset mappings.

# Linagee Name Service Use Cases
1. **Name Resolution**: Linagee Name Registrar offers support for name resolution, enabling users to seamlessly map human-readable names to Ethereum addresses. This flexibility caters to various use cases, from simplified address resolution to more complex on-chain asset resolution.

2. **Permanent Content Delivery Network**: Linagee Name Registrar enables easy access to permanent website storage by linking assets stored within the Ethereum Virtual Machine (EVM) to Linagee names. A prime example is "ecdn.og," serving as an immutable and irrevocable EthFS Content Delivery Network (CDN) that leverages Linagee's capabilities.

3. **Semi-Permanent Assets in calldata**: Linagee Name Registrar empowers users to point their domain names to semi-permanent assets stored in calldata. This feature is exemplified by "lnrforever.og," demonstrating how Linagee can be harnessed to associate domain names with ever-evolving content stored in calldata, further expanding the possibilities of on-chain asset resolution.


# Specification
## Overview


**Linagee Name Registrar Specifications:**

The Linagee Name Registrar is a comprehensive solution composed of five main components, each playing a vital role in enabling permanent, human-readable domains on the Ethereum blockchain. These components are designed to provide users with control, flexibility, and ease of use:

1. **The Registrar:**
   - The registrar is a fundamental contract that facilitates the mapping of registered names to their respective owner's Ethereum addresses. It forms the core of Linagee Name Registrar, ensuring that each name is associated with its owner.
   
2. **The Resolver:**
   - The resolver contract serves as a crucial layer of the Linagee Name Registrar ecosystem. It allows users to link their Linagee names to their primary Ethereum address, providing a user-friendly means of address resolution. Additionally, the resolver contract permits users to delegate name control to another address without relinquishing ownership. Owners can also utilize this contract to set text records, which is particularly valuable for pointing to other on-chain assets.

3. **The Wrapper Contract:**
   - Linagee names predate the ERC-721 standard, and the wrapper contract is introduced to address the need for compatibility and usability. This contract enables users to wrap and unwrap their Linagee names, allowing for straightforward trading and viewing of these unique digital assets. The wrapper contract streamlines the user experience and ensures that Linagee names can be easily managed and exchanged.

4. **The LNR-Web Contract:**
   - The LNR-Web contract serves as an innovative addition to the Linagee Name Registrar ecosystem, enhancing the utility and versatility of Linagee names. This contract empowers users to upload data in the form of Ethereum Virtual Machine (EVM) calldata, enabling the creation of semi-permanent on-chain websites. This functionality is vividly demonstrated by lnrforever.og, highlighting how Linagee names can be used to point to evolving content stored in calldata, opening new possibilities for on-chain website development and content management.
     
5. **The CDN Contract:**
   - The Linagee domain ecdn.og is permanently linked to a smart contract that operates as a Content Delivery Network (CDN) within the Ethereum ecosystem. Specifically designed to integrate seamlessly with EthFS, it empowers developers to efficiently utilize libraries stored on EthFS while adhering to the EIP-4804 standard. By doing so, ecdn.og significantly mitigates the redundancy of data on the blockchain, resulting in cost savings and conservation of valuable chain space. This innovation not only optimizes the economic aspects of on-chain operations but also facilitates streamlined website development. As an increasing number of libraries are uploaded.

## Name Syntax and Normalization

In the Linagee Name Registrar (LNR), the syntax of names is a critical element that ensures compatibility and consistency in the system. To maintain a well-structured and uniform approach to name registration, LNR follows specific guidelines:

1. **Name Length Limitation:**
   - Names registered with LNR are limited to a maximum length of 32 bytes. This restriction ensures that names remain concise, readable, and suitable for efficient on-chain processing.

2. **Normalization Standard (ENSIP-15):**
   - LNR adheres to the ENSIP-15 Normalization Standard, which defines a set of rules for normalizing names. This standard ensures that all registered names are treated consistently, minimizing potential ambiguities and conflicts. By adhering to the normalization standard, LNR ensures that similar names with different representations are resolved consistently.

   - The ENSIP-15 Normalization Standard encompasses processes such as converting names to lowercase, removing leading and trailing whitespace, and performing Unicode normalization. This normalization process guarantees that registered names are in their most standardized and compatible form for effective use within the Linagee Name Registrar ecosystem.

By adhering to the specified name length limitation and the ENSIP-15 Normalization Standard, LNR maintains a high level of consistency, usability, and compatibility across all registered names, ensuring that users can seamlessly interact with and resolve Linagee names in a reliable and user-friendly manner. These standards contribute to the clarity and precision of name registration, making Linagee an accessible and efficient solution for permanent human-readable domains on the Ethereum blockchain.



## Rationale

The integration of on-chain permanent domains as both address mappings and CDNs aligns seamlessly with EIP-4804, offering a trustless mapping solution that not only enhances data permanence but also promotes decentralized content delivery, ensuring a robust and censorship-resistant infrastructure for the Ethereum ecosystem.

## Security Considerations

No security considerations were found.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).


# Appendix A: Registrar Implementation

```solidity
/**
 *Submitted for verification at Etherscan.io on 2022-10-04
*/

contract NameRegister {
  function addr(bytes32 _name) constant returns (address o_owner) {}
  function name(address _owner) constant returns (bytes32 o_name) {}
}
contract Registrar is NameRegister {
  event Changed(bytes32 indexed name);
  event PrimaryChanged(bytes32 indexed name, address indexed addr);
  function owner(bytes32 _name) constant returns (address o_owner) {}
  function addr(bytes32 _name) constant returns (address o_address) {}
  function subRegistrar(bytes32 _name) constant returns (address o_subRegistrar) {}
  function content(bytes32 _name) constant returns (bytes32 o_content) {}
  function name(address _owner) constant returns (bytes32 o_name) {}
}

contract GlobalRegistrar is Registrar {
  struct Record {
    address owner;
    address primary;
    address subRegistrar;
    bytes32 content;
    uint value;
    uint renewalDate;
  }
  function Registrar() {
    // TODO: Populate with hall-of-fame.
  }
  function reserve(bytes32 _name) {
    // Don't allow the same name to be overwritten.
    // TODO: bidding mechanism
    if (m_toRecord[_name].owner == 0) {
      m_toRecord[_name].owner = msg.sender;
      Changed(_name);
    }
  }
  /*
  TODO
  > 12 chars: free
  <= 12 chars: auction:
  1. new names are auctioned
  - 7 day period to collect all bid bytes32es + deposits
  - 1 day period to collect all bids to be considered (validity requires associated deposit to be >10% of bid)
  - all valid bids are burnt except highest - difference between that and second highest is returned to winner
  2. remember when last auctioned/renewed
  3. anyone can force renewal process:
  - 7 day period to collect all bid bytes32es + deposits
  - 1 day period to collect all bids & full amounts - bids only uncovered if sufficiently high.
  - 1% of winner burnt; original owner paid rest.
  */
  modifier onlyrecordowner(bytes32 _name) { if (m_toRecord[_name].owner == msg.sender) _ }
  function transfer(bytes32 _name, address _newOwner) onlyrecordowner(_name) {
    m_toRecord[_name].owner = _newOwner;
    Changed(_name);
  }
  function disown(bytes32 _name) onlyrecordowner(_name) {
    if (m_toName[m_toRecord[_name].primary] == _name)
    {
      PrimaryChanged(_name, m_toRecord[_name].primary);
      m_toName[m_toRecord[_name].primary] = "";
    }
    delete m_toRecord[_name];
    Changed(_name);
  }
  function setAddress(bytes32 _name, address _a, bool _primary) onlyrecordowner(_name) {
    m_toRecord[_name].primary = _a;
    if (_primary)
    {
      PrimaryChanged(_name, _a);
      m_toName[_a] = _name;
    }
    Changed(_name);
  }
  function setSubRegistrar(bytes32 _name, address _registrar) onlyrecordowner(_name) {
    m_toRecord[_name].subRegistrar = _registrar;
    Changed(_name);
  }
  function setContent(bytes32 _name, bytes32 _content) onlyrecordowner(_name) {
    m_toRecord[_name].content = _content;
    Changed(_name);
  }
  function owner(bytes32 _name) constant returns (address) { return m_toRecord[_name].owner; }
  function addr(bytes32 _name) constant returns (address) { return m_toRecord[_name].primary; }
//  function subRegistrar(bytes32 _name) constant returns (address) { return m_toRecord[_name].subRegistrar; } // TODO: bring in on next iteration.
  function register(bytes32 _name) constant returns (address) { return m_toRecord[_name].subRegistrar; }  // only possible for now
  function content(bytes32 _name) constant returns (bytes32) { return m_toRecord[_name].content; }
  function name(address _owner) constant returns (bytes32 o_name) { return m_toName[_owner]; }
  mapping (address => bytes32) m_toName;
  mapping (bytes32 => Record) m_toRecord;
}
```
# Appendix B: Resolver Implementation


```solidity
contract LNR_RESOLVER_V3 is Initializable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() initializer public {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        onlyOwner
        override
    {}

    event NewController(bytes32 indexed name, address indexed controller);
    event NewPrimary(bytes32 indexed name, address indexed primary);

    address public constant lnrAddress = 0x5564886ca2C518d1964E5FCea4f423b41Db9F561;
    mapping(bytes32 => address) public resolveAddress;  // maps a LNR domain name to an an address
    mapping(bytes32 => address) public controller;      // stores controller for each name, controller or owner can change domain information
    mapping(address => bytes32) public primary;         // stores the primary name of an address

///////////////////////////////////////
// DO NOT CHANGE ANYTHING BETWEEN    //
// LINE 19 and  LINE 43              //
///////////////////////////////////////

    struct TextRecords {
      bool initialized;
      mapping(string => string) keyValue;
    }
    mapping(bytes32 => TextRecords) public userTextRecords;

    event SetTextRecord(bytes32 indexed name, string indexed key, string indexed value);

    function getResolveAddress(bytes32 _name) public view returns (address){
      return resolveAddress[_name];
    }

    function resolve(string calldata _domain) public view returns (address){
      bytes memory domainBytes = bytes(_domain);
      require(domainBytes.length < 36, "Too long"); // bytes32 + .og = 35 bytes
      require(domainBytes[domainBytes.length-1] == 0x67 && domainBytes[domainBytes.length-2] == 0x6F && domainBytes[domainBytes.length-3] == 0x2E, "invalid domain"); // must end in .og
      delete domainBytes[domainBytes.length-1];
      delete domainBytes[domainBytes.length-2];
      delete domainBytes[domainBytes.length-3];
      uint i;
      // ensures there are no other periods in the name, it must be a primary and not a subdomain!
      for(;i<domainBytes.length-3;){
        require(domainBytes[i] != 0x2E, "this is a subdomain");
        unchecked {++i;}
      }
      return resolveAddress[bytes32(domainBytes)];
    }

    // make sure that the _addr is the authorized to make changes (controller or the owner)
    function verifyIsNameOwner(bytes32 _name, address _addr) public view returns(bool) {
        if((controller[_name] == _addr) || (ILNR(lnrAddress).owner(_name) == _addr))
          return true;
        return false;
    }

    // allow the owner to designate a new controller
    function setController(bytes32 _name, address _controller) public nonReentrant {
      require((ILNR(lnrAddress).owner(_name) == msg.sender) , "Not yours");
      controller[_name] = _controller;
      emit NewController(_name, _controller);
    }

    function unsetController(bytes32 _name) public {
      setController(_name, address(0));
    }

    // setting the primary with map the name to the primary address and the address to the name
    function setPrimary(bytes32 _name) public nonReentrant {
      require(verifyIsNameOwner(_name, msg.sender), "Not yours");
      delete resolveAddress[primary[msg.sender]];
      delete primary[resolveAddress[_name]];   // remove primary from old primary address
      primary[msg.sender] = _name;             // set new primary
      resolveAddress[_name] = msg.sender;      // set new resolver
      emit NewPrimary(_name, msg.sender);
    }

    // unset the primary for the msg.sender, need to remove
    function unsetPrimary() public nonReentrant {
      delete resolveAddress[primary[msg.sender]];
      delete primary[msg.sender];
      emit NewPrimary(0x00, msg.sender);
    }

    function getTextRecord(bytes32 _name, string calldata _key) public view returns (string memory){
       return userTextRecords[_name].keyValue[_key];

    }

    // setting a key value text record object to the name
    function setTextRecord(bytes32 _name, string calldata _key, string calldata _value) public nonReentrant {
      require(verifyIsNameOwner(_name, msg.sender), "Not yours");
      userTextRecords[_name].keyValue[_key] = _value;
      emit SetTextRecord(_name, _key, _value);
    }

    function unsetTextRecord(bytes32 _name, string calldata _key) public nonReentrant {
        require(verifyIsNameOwner(_name, msg.sender), "Not yours");
        delete userTextRecords[_name].keyValue[_key];
        emit SetTextRecord(_name, "", "");

    }

}
```


# Appendix C: Wrapper Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";



interface Linagee {
  function transfer (bytes32 nameId, address receiver) external;
  function owner (bytes32 nameId) view external returns(address);
  function setContent(bytes32 _node, bytes32 _hash) external;
  function setSubRegistrar(bytes32 _param1, address _param2) external;
  function setAddress(bytes32 _param1, address _param2, bool _param3) external;
}


contract LinageeNameWrapper is ERC721, ERC721Enumerable, Ownable {

   
    
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;
    mapping(uint256 => bytes32) public idToName;
    mapping(bytes32 => uint256) public nameToId;
    mapping(bytes32 => address) public waitForWrap;
    string _baseUri;
    bool proxyMethodsAvail = false;
    bool wrapEnabled = true;
    Linagee public nameBytes = Linagee(0x5564886ca2C518d1964E5FCea4f423b41Db9F561);

    event Wrapped(uint256 indexed pairId, address indexed owner, bytes32 namer);
    event Unwrapped(uint256 indexed pairId, address indexed owner, bytes32 namer);
    
    constructor(string memory _uri) ERC721("ETHRegistrarLinageeWrapper", "ERLW") {
        _tokenIds._value = 1;
        _baseUri = _uri;
    }


    function changeProxyAvail() public onlyOwner{
        proxyMethodsAvail = !proxyMethodsAvail;
    }

    function changeWrapEnabled() public onlyOwner{
        wrapEnabled = !wrapEnabled;
    }



    function getNameOwner(bytes32 nameId) view public returns(address) {
        return nameBytes.owner(nameId);
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseUri;
    }

    function setBaseURI(string memory _uri) public onlyOwner {
        _baseUri = _uri;
    }

    function createWrapper(bytes32 _name) public {
        require(getNameOwner(_name) == msg.sender, "You are not the owner");
        require(wrapEnabled,"Wrapping is not enabled");
        waitForWrap[_name] = msg.sender;
    }

    function wrap(bytes32 _name) public {
    
        require(getNameOwner(_name) == address(this), "Contract is not the owner. Please transfer ownership");
        require(waitForWrap[_name] == msg.sender,"You are not waiting for this wrap!");
        require(wrapEnabled,"Wrapping is not enabled");

        uint256 tokenId = _tokenIds.current();
        _tokenIds.increment();
       
        _mint(msg.sender,tokenId);

        idToName[tokenId] = _name; 
        nameToId[_name] = tokenId;


        delete waitForWrap[_name];
        emit Wrapped(tokenId, msg.sender,_name);
    }

    function unwrap(uint256 _tokenId) public {

        require(ownerOf(_tokenId) == msg.sender, "You are not the owner");
        bytes32 namer = idToName[_tokenId];
        nameBytes.transfer(namer,msg.sender);
        delete idToName[_tokenId];
        delete nameToId[namer];
        _burn(_tokenId);

        emit Unwrapped(_tokenId, msg.sender,namer);
    }
  

    function proxySetContent(uint256 _tokenId, bytes32 _hash) public {
        require(proxyMethodsAvail,"Proxy Methods are not available right now");
        require(ownerOf(_tokenId) == msg.sender,"You need to be the owner");
        nameBytes.setContent(idToName[_tokenId], _hash);

    }
    function proxySetSubRegistrar(uint256 _tokenId, address _param2) payable public {
        require(proxyMethodsAvail,"Proxy Methods are not available right now");
        require(ownerOf(_tokenId) == msg.sender,"You need to be the owner");
        nameBytes.setSubRegistrar(idToName[_tokenId],_param2);
        
    } 
    function proxySetAddress(uint256 _tokenId, address _param2, bool _param3) public {
        require(proxyMethodsAvail,"Proxy Methods are not available right now");
        require(ownerOf(_tokenId) == msg.sender,"You need to be the owner");
        nameBytes.setAddress(idToName[_tokenId],  _param2,  _param3);
    }

    

    // The following functions are overrides required by Solidity.

    function _beforeTokenTransfer(address from, address to, uint256 tokenId)
        internal
        override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
```
# Appendix D: LNR-Web Implementation

``` solidity
/**
 *Submitted for verification at Etherscan.io on 2023-02-14
*/

// SPDX-License-Identifier: DERP
// By Derp Herpenstein derp://derpnation.og, https://www.derpnation.xyz

pragma solidity ^0.8.4;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}


interface ILNR_RESOLVER {
   function verifyIsNameOwner(bytes32 _name, address _addr) external view returns(bool);
}

contract LNR_WEB_V1 is ReentrancyGuard {

    event NewAsset(bytes32 indexed assetHash, string assetName, string assetDescription);
    event NewWebsite(bytes32 indexed domain, bytes data);
    event NewState(bytes32 indexed domain, address indexed user, uint256 version, bytes state);

    struct Website{
      bytes32 pageHash;
      bytes32 pageTxHash;
    }

    address public constant lnrResolverAddress = 0x6023E55814DC00F094386d4eb7e17Ce49ab1A190; // resolver
    mapping(bytes32 => Website) public lnrWebsites; // maps a domain to a web address

  function getWebsite(bytes32 _domain) public view returns(Website memory){
    return(lnrWebsites[_domain]);
  }

  function updateWebsite(bytes32 _domain, bytes32 _pageHash, bytes32 _pageTxHash, bytes calldata _data) public nonReentrant{
    require(ILNR_RESOLVER(lnrResolverAddress).verifyIsNameOwner(_domain, msg.sender) == true, "Not your domain");
    lnrWebsites[_domain].pageHash = _pageHash;
    lnrWebsites[_domain].pageTxHash = _pageTxHash;
    emit NewWebsite(_domain, _data);
  }

  function uploadAssets(bytes32[] calldata _assetHash, string[] calldata _assetName, string[] calldata _assetHeaders, 
                        string[] calldata _assetDescription, bytes[] calldata _assetData) external {
    uint i = 0;
    for(; i< _assetName.length;){
      emit NewAsset(_assetHash[i], _assetName[i], _assetDescription[i]);
      unchecked {++i;}
    }
  }

  function uploadAsset( bytes32 _assetHash, bytes32 _nextChunk, string calldata _assetName, string calldata _assetHeaders, 
                        string calldata _assetDescription, bytes calldata _assetData) external {
    emit NewAsset(_assetHash, _assetName, _assetDescription);
  }

  function updateState(bytes32 _domain, uint256 _version, bytes calldata _state) external {
    emit NewState(_domain, msg.sender, _version, _state);
  }

}
```
# Appendix E: CDN Implementation
```
/**
 *Submitted for verification at Etherscan.io on 2023-04-30
*/

// File: contracts/Base64.sol



pragma solidity >=0.6.0;

/// @title Base64
/// @author Brecht Devos - <brecht@loopring.org>
/// @notice Provides functions for encoding/decoding base64
library Base64 {
    string internal constant TABLE_ENCODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    bytes  internal constant TABLE_DECODE = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                            hex"00000000000000000000003e0000003f3435363738393a3b3c3d000000000000"
                                            hex"00000102030405060708090a0b0c0d0e0f101112131415161718190000000000"
                                            hex"001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132330000000000";

    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return '';

        // load the table into memory
        string memory table = TABLE_ENCODE;

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((data.length + 2) / 3);

        // add some extra buffer at the end required for the writing
        string memory result = new string(encodedLen + 32);

        assembly {
            // set the actual output length
            mstore(result, encodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {}
            {
                // read 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // write 4 characters
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr( 6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(        input,  0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            // padding with '='
            switch mod(mload(data), 3)
            case 1 { mstore(sub(resultPtr, 2), shl(240, 0x3d3d)) }
            case 2 { mstore(sub(resultPtr, 1), shl(248, 0x3d)) }
        }

        return result;
    }

    function decode(string memory _data) internal pure returns (bytes memory) {
        bytes memory data = bytes(_data);

        if (data.length == 0) return new bytes(0);
        require(data.length % 4 == 0, "invalid base64 decoder input");

        // load the table into memory
        bytes memory table = TABLE_DECODE;

        // every 4 characters represent 3 bytes
        uint256 decodedLen = (data.length / 4) * 3;

        // add some extra buffer at the end required for the writing
        bytes memory result = new bytes(decodedLen + 32);

        assembly {
            // padding with '='
            let lastBytes := mload(add(data, mload(data)))
            if eq(and(lastBytes, 0xFF), 0x3d) {
                decodedLen := sub(decodedLen, 1)
                if eq(and(lastBytes, 0xFFFF), 0x3d3d) {
                    decodedLen := sub(decodedLen, 1)
                }
            }

            // set the actual output length
            mstore(result, decodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 4 characters at a time
            for {} lt(dataPtr, endPtr) {}
            {
               // read 4 characters
               dataPtr := add(dataPtr, 4)
               let input := mload(dataPtr)

               // write 3 bytes
               let output := add(
                   add(
                       shl(18, and(mload(add(tablePtr, and(shr(24, input), 0xFF))), 0xFF)),
                       shl(12, and(mload(add(tablePtr, and(shr(16, input), 0xFF))), 0xFF))),
                   add(
                       shl( 6, and(mload(add(tablePtr, and(shr( 8, input), 0xFF))), 0xFF)),
                               and(mload(add(tablePtr, and(        input , 0xFF))), 0xFF)
                    )
                )
                mstore(resultPtr, shl(232, output))
                resultPtr := add(resultPtr, 3)
            }
        }

        return result;
    }
}
// File: contracts/ethfsCDN.sol


pragma solidity ^0.8.13;


struct Content {
    bytes32 checksum;
    address pointer;
}

struct File {
    uint256 size; // content length in bytes, max 24k
    Content[] contents;
}

function read(File memory file) view returns (string memory contents) {
    Content[] memory chunks = file.contents;

    // Adapted from https://gist.github.com/xtremetom/20411eb126aaf35f98c8a8ffa00123cd
    assembly {
        let len := mload(chunks)
        let totalSize := 0x20
        contents := mload(0x40)
        let size
        let chunk
        let pointer

        // loop through all pointer addresses
        // - get content
        // - get address
        // - get data size
        // - get code and add to contents
        // - update total size

        for { let i := 0 } lt(i, len) { i := add(i, 1) } {
            chunk := mload(add(chunks, add(0x20, mul(i, 0x20))))
            pointer := mload(add(chunk, 0x20))

            size := sub(extcodesize(pointer), 1)
            extcodecopy(pointer, add(contents, totalSize), 1, size)
            totalSize := add(totalSize, size)
        }

        // update contents size
        mstore(contents, sub(totalSize, 0x20))
        // store contents
        mstore(0x40, add(contents, and(add(totalSize, 0x1f), not(0x1f))))
    }
}

using {
    read
} for File global;

interface IContentStore {
    event NewChecksum(bytes32 indexed checksum, uint256 contentSize);

    error ChecksumExists(bytes32 checksum);
    error ChecksumNotFound(bytes32 checksum);

    function pointers(bytes32 checksum) external view returns (address pointer);

    function checksumExists(bytes32 checksum) external view returns (bool);

    function contentLength(bytes32 checksum)
        external
        view
        returns (uint256 size);

    function addPointer(address pointer) external returns (bytes32 checksum);

    function addContent(bytes memory content)
        external
        returns (bytes32 checksum, address pointer);

    function getPointer(bytes32 checksum)
        external
        view
        returns (address pointer);
}

interface IFileStore {
    event FileCreated(
        string indexed indexedFilename,
        bytes32 indexed checksum,
        string filename,
        uint256 size,
        bytes metadata
    );
    event FileDeleted(
        string indexed indexedFilename,
        bytes32 indexed checksum,
        string filename
    );

    error FileNotFound(string filename);
    error FilenameExists(string filename);
    error EmptyFile();

    function contentStore() external view returns (IContentStore);

    function files(string memory filename)
        external
        view
        returns (bytes32 checksum);

    function fileExists(string memory filename) external view returns (bool);

    function getChecksum(string memory filename)
        external
        view
        returns (bytes32 checksum);

    function getFile(string memory filename)
        external
        view
        returns (File memory file);

    function createFile(string memory filename, bytes32[] memory checksums)
        external
        returns (File memory file);

    function createFile(
        string memory filename,
        bytes32[] memory checksums,
        bytes memory extraData
    ) external returns (File memory file);

    function deleteFile(string memory filename) external;
}

// By: Derp Herpenstein - web3://derpnation.og, www.derpnation.xyz, @0xDerpNation
contract EthFSCDN {

    address constant fileStorageAddress = 0x9746fD0A77829E12F8A9DBe70D7a322412325B91; // ethFS mainnet

    function resolveMode() external pure virtual returns (bytes32) {
        return "manual";
    }
    
    function returnBytesInplace(bytes memory content) internal pure {
        // equal to return abi.encode(content)
        uint256 size = content.length + 0x40; // pointer + size
        size = (size + 0x20 + 0x1f) & ~uint256(0x1f);
        assembly {
            // (DATA CORRUPTION): the caller method must be "external returns (bytes)", cannot be public!
            mstore(sub(content, 0x20), 0x20)
            return(sub(content, 0x20), size)
        }
    }
    
    fallback(bytes calldata _pathinfo) external returns (bytes memory)  {
        bytes memory content;
        if ( (_pathinfo.length == 0) || (_pathinfo[_pathinfo.length - 1] == 0x2f)) {
            return bytes("Error: invalid path");
        }
        if(_pathinfo[_pathinfo.length-1] == 0x7A && _pathinfo[_pathinfo.length-2] == 0x67 && _pathinfo[_pathinfo.length-3] == 0x2E)
            content = getFile(string(_pathinfo[1:]),fileStorageAddress, true);
        else
            content = getFile(string(_pathinfo[1:]),fileStorageAddress, false);
        returnBytesInplace(content);
    }

    // returns the raw data, or the decoded data
    function getFile(string memory _fileName, address _contractAddress, bool _returnRaw) public view returns (bytes memory fileBytes) {
        IFileStore fileStore = IFileStore(_contractAddress);
        if(_returnRaw)
            return ( bytes( fileStore.getFile(_fileName).read() ) );
        return ( bytes( Base64.decode(fileStore.getFile(_fileName).read())  ) );
    }
    
    function getFileAsString(string memory _fileName, address _contractAddress, bool _returnRaw) public view returns (string memory fileString){
        return string( getFile(_fileName, _contractAddress, _returnRaw) );
    }   
}
```

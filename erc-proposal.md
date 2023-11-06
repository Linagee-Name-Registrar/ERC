---
eip: -
title: Linagee Name Registrar - Specification
author: Mason Keresty <linagee.vision@gmail.com>
status: Proposal
type: Standards Track
category: ERC
created: 2023-11-06
---

# Abstract

This draft EIP describes the Linagee Name Registrar (LNR) as a standard and protocol for the establishment of permanent, human-readable domains on the Ethereum blockchain. This innovative registrar contract is distinguished as the oldest NFT (Non-Fungible Token) contract on Ethereum, embodying the core principles of decentralization and fairness that are at the heart of the Ethereum ecosystem.

One of the distinguishing features of the Linagee Name Registrar is its unwavering commitment to user accessibility and inclusivity. The Linagee registrar contract revolutionizes the domain registration process by offering names that are free to register and never expire. This open and sustainable approach sets Linagee apart as an ideal solution for not only address resolution but also on-chain asset resolution. It provides a reliable framework for mapping human-readable names to Ethereum addresses, enhancing the user experience and fostering the widespread adoption of blockchain technology.

With this approach Linagee domain names allow for ease of access of permanent website storage via assets stored in the EVM. The best example of this being ecdn.og as a permanent, unrevokable ethFS CDN. Additionally, these domain names are structured to leverage the capabilities of the web3 access protocol described in ERC-4804.

The Linagee Name Registrar ERC standard redefines the landscape of decentralized domain management by creating an accessible, permanent, and user-centric solution that aligns with the fundamental principles of Ethereum.

# Motivation


**Motivation for Linagee Name Registrar**

The Linagee Name Registrar represents a compelling solution to address the existing limitations and challenges associated with other Ethereum Name Registrars. It serves as a progressive response to these challenges, striving to enhance the user experience while promoting true ownership, complete decentralization, and versatile name resolution capabilities. 

**Shortcomings of Other Ethereum Name Registrars:**

1. **Limited True Ownership**: Unlike Linagee, other Ethereum name registrars often fall short in providing true ownership of domain names. These registrars may not offer users complete control over their domains, compromising the fundamental principles of blockchain decentralization.

2. **Lack of Full On-Chain Functionality**: Many existing Ethereum name registrars fail to leverage the full potential of the blockchain. They might rely on centralized or off-chain components, hindering their ability to deliver fully decentralized and trustless solutions.

**Use Cases for Linagee Name Registrar:**

1. **Multiple Types of Name Resolution**: Linagee Name Registrar offers support for multiple types of name resolution, enabling users to seamlessly map human-readable names to Ethereum addresses. This flexibility caters to various use cases, from simplified address resolution to more complex on-chain asset resolution.

2. **Permanent Website Storage**: Linagee Name Registrar enables easy access to permanent website storage by linking assets stored within the Ethereum Virtual Machine (EVM) to Linagee names. A prime example is "ecdn.og," serving as an immutable and irrevocable EthFS Content Delivery Network (CDN) that leverages Linagee's capabilities.

3. **Semi-Permanent Assets in calldata**: Linagee Name Registrar empowers users to point their domain names to semi-permanent assets stored in calldata. This feature is exemplified by "lnrforever.og," demonstrating how Linagee can be harnessed to associate domain names with ever-evolving content stored in calldata, further expanding the possibilities of on-chain asset resolution.

The Linagee Name Registrar thus presents an innovative solution that not only addresses the shortcomings of existing Ethereum name registrars but also unlocks new dimensions of versatility in name resolution, asset storage, and ownership within the Ethereum ecosystem. It encourages a decentralized, user-centric approach, positioning itself as a catalyst for the evolution of the Ethereum blockchain.
# Specification
## Overview


**Linagee Name Registrar Specifications:**

The Linagee Name Registrar (LNR) is a comprehensive solution composed of four main components, each playing a vital role in enabling permanent, human-readable domains on the Ethereum blockchain. These components are designed to provide users with control, flexibility, and ease of use:

1. **The Registrar:**
   - The registrar is a fundamental contract that facilitates the mapping of registered names to their respective owner's Ethereum addresses. It forms the core of Linagee Name Registrar, ensuring that each name is associated with its owner.
   
2. **The Resolver:**
   - The resolver contract serves as a crucial layer of the Linagee Name Registrar ecosystem. It allows users to link their Linagee names to their primary Ethereum address, providing a user-friendly means of address resolution. Additionally, the resolver contract permits users to delegate name control to another address without relinquishing ownership. Owners can also utilize this contract to set text records, which is particularly valuable for pointing to other on-chain assets. A prime example of this functionality can be observed in the integration of ecdn.og, demonstrating Linagee's capacity to seamlessly point to on-chain assets such as content delivery networks.

3. **The Wrapper Contract:**
   - Linagee names predate the ERC-721 standard, and the wrapper contract is introduced to address the need for compatibility and usability. This contract enables users to wrap and unwrap their Linagee names, allowing for straightforward trading and viewing of these unique digital assets. The wrapper contract streamlines the user experience and ensures that Linagee names can be easily managed and exchanged.

4. **The LNR-Web Contract:**
   - The LNR-Web contract serves as an innovative addition to the Linagee Name Registrar ecosystem, enhancing the utility and versatility of Linagee names. This contract empowers users to upload data in the form of Ethereum Virtual Machine (EVM) calldata, enabling the creation of semi-permanent on-chain websites. This functionality is vividly demonstrated by lnrforever.og, highlighting how Linagee names can be used to point to evolving content stored in calldata, opening new possibilities for on-chain website development and content management.

These four main components collectively make up the Linagee Name Registrar, an Ethereum ERC proposal that addresses the shortcomings of existing Ethereum name registrars, providing a user-centric, versatile, and decentralized solution for permanent human-readable domains on the Ethereum blockchain.

## Name Syntax and Normalization

In the Linagee Name Registrar (LNR), the syntax of names is a critical element that ensures compatibility and consistency in the system. To maintain a well-structured and uniform approach to name registration, LNR follows specific guidelines:

1. **Name Length Limitation:**
   - Names registered with LNR are limited to a maximum length of 32 bytes. This restriction ensures that names remain concise, readable, and suitable for efficient on-chain processing.

2. **Normalization Standard (ENSIP-15):**
   - LNR adheres to the ENSIP-15 Normalization Standard, which defines a set of rules for normalizing names. This standard ensures that all registered names are treated consistently, minimizing potential ambiguities and conflicts. By adhering to the normalization standard, LNR ensures that similar names with different representations are resolved consistently.

   - The ENSIP-15 Normalization Standard encompasses processes such as converting names to lowercase, removing leading and trailing whitespace, and performing Unicode normalization. This normalization process guarantees that registered names are in their most standardized and compatible form for effective use within the Linagee Name Registrar ecosystem.

By adhering to the specified name length limitation and the ENSIP-15 Normalization Standard, LNR maintains a high level of consistency, usability, and compatibility across all registered names, ensuring that users can seamlessly interact with and resolve Linagee names in a reliable and user-friendly manner. These standards contribute to the clarity and precision of name registration, making Linagee an accessible and efficient solution for permanent human-readable domains on the Ethereum blockchain.


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

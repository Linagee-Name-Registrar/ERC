---
eip: 7584
title: ERC-7584 On-Chain Name Registrar
description: Defines on-chain domain names and their use for address mapping and decentralized content delivery networks (CDNs).
author: Linagee Name Registrar (@Linagee-Name-Registrar), Mason Keresty (@mkeresty) <linagee.vision@gmail.com>, Derp Herpenstein (@DerpHerpenstein) <derp@derpfinance.com>, Chriton (@Chriton) <defisummer@gmail.com>
discussions-to: https://ethereum-magicians.org/t/eip-linagee-name-registrar-and-ethereum-content-delivery-network/17596
status: Draft
type: Standards Track
category: ERC
created: 2023-12-27
requires: 4804, 7584
---

## Abstract

This EIP introduces a new standard that delineates on-chain permanent domain names and outlines their utilization for address mapping and their use in decentralized content delivery networks (CDNs) for [ERC-4804](./eip-4804.md).

## Motivation

ERC-4804 defines a `web3://`-scheme RFC 2396 URI to call a smart contract either by its address or a **name** from name service.  If a **name** is specified, the standard specifies a way to resolve the contract address from the name. This EIP expands ERC-4804 to include an on-chain service and its use for permanent asset mappings.

The **permanent** nature of these names make them ideal for securely resolving immutable on-chain assets.

# Use Cases
1. **Name Resolution**: Enables users to seamlessly map human-readable names to Ethereum addresses. This flexibility caters to various use cases, from simplified address resolution to more complex on-chain asset resolution. 

	 Linagee names, for example are denoted by the top level domain (TLD) "**.og**".

2. **Permanent Content Delivery Network**: Enables easy access to permanent website storage by linking assets stored within the Ethereum Virtual Machine (EVM) to domain names. A prime example is **ecdn.og**, serving as an immutable and irrevocable Ethereum File Storage (EthFS) Content Delivery Network (CDN).

3. **Semi-Permanent Assets in calldata**: Empowers users to point their domain names to semi-permanent assets stored in calldata. This feature is explained further in Appendix E.



## Specification
### Overview


**Registrar Specifications:**

The Registrar is a comprehensive solution composed of four main components, each playing a vital role in enabling permanent, human-readable domain names on the Ethereum blockchain. These components are designed to provide users with control, flexibility, and ease of use:

1. **Registrar Contract**
   - The registrar is a fundamental contract that facilitates the registration of names and the mapping of registered names to their respective owner's Ethereum addresses. It forms the core of the Registrar, ensuring that each name is associated with its owner.
   - These domain names are **permanently** owned, unless transferred by the owner. No renewals necessary.
   - **Core functions**:
	   - ```mapping (bytes32 => Record) m_toRecord;```
	   - ```function reserve(bytes32 _name)``` 
		   - Creates a mapping of name to address if it is not currently owned.
	   - ```function transfer(bytes32 _name, address _newOwner) onlyrecordowner(_name)``` 
		   - Allows the owner of a name to transfer it to another address.
	   - ```function owner(bytes32 _name) constant returns (address) { return m_toRecord[_name].owner; }``` 
		   - Returns the owner of a given name
   
2. **Resolver Contract**
   - The resolver contract allows users to link their domain names to their primary Ethereum address, providing a user-friendly means of address resolution. Additionally, the resolver contract permits users to delegate name control to another address without relinquishing ownership. Owners can also utilize this contract to set text records, which is particularly valuable for pointing to other on-chain assets.
   - **Core functions:**
	   - ```mapping(bytes32 => address) public resolveAddress; ```
	   - ```mapping(bytes32 => address) public controller;  ```
	   - ```mapping(address => bytes32) public primary; ```
	   - ```mapping(bytes32 => TextRecords) public userTextRecords;```
	   - ```function setPrimary(bytes32 _name)``` 
		   - Allows the user to create a mapping from name to address for a name the own or control.
	   - ```function setTextRecord(bytes32 _name, string calldata _key, string calldata _value)``` 
		   - Allows the owner of the name to create a *key: value* mapping associated with a specific name.
	   - ```function setController(bytes32 _name, address _controller)``` 
		   - Allows the owner of a name to authorize another address to use the name as their primary name.

3. **Wrapper Contract**
   - Linagee names predate the [ERC-721](./eip-721.md) standard, and the wrapper contract is introduced to address the need for compatibility and usability. This contract enables users to wrap and unwrap their Linagee names, allowing for straightforward trading and viewing of these unique digital assets. The wrapper contract streamlines the user experience and ensures that Linagee names can be easily managed and exchanged.
   - **Core functions**
	   - ```function createWrapper(bytes32 _name)``` Allows the owner of an unwrapped name to create a wrapper. Must be called prior to transferring the name to the wrapper.
	   - ```function wrap(bytes32 _name)``` Must be called after the wrapper is created and after the name is transferred to the wrapper contract. This function creates an ERC-721 token to represent the name. Only the owner of the ERC-721 token may unwrap the name.
	   - ```function unwrap(uint256 _tokenId)``` Can only be called by the owner of the ERC-721 token. When called the ERC-721 token is destroyed, and the linagee name is transferred from the wrapper contract to the caller.
	   
4. **The CDN Contract**
   - The Linagee name **ecdn.og** is permanently linked to a smart contract that operates as a Content Delivery Network (CDN) within the Ethereum ecosystem. Specifically designed to integrate seamlessly with the [EthFS](https://ethfs.xyz/) contract, it empowers developers to efficiently utilize libraries stored on EthFS while adhering to the ERC-4804 standard. By doing so, ecdn.og significantly mitigates the redundancy of data on the blockchain, resulting in cost savings and conservation of valuable chain space.
   - The linking between ecdn.og and the CDN contract is done through the **setTextRecord** function in the Resolver Contract. with the key:value pair being ```contentcontract: 0x4F53Eae17346d6c0f96215Af157c7F8e093E17F1```.
   - ecdn.og is owned by a burn address, making this link **permanent**.
   - In practice a library on EthFS such as SimpleCss could be used within an on-chain website in this manner:
    ```
    <link rel="stylesheet" href="web3://ecdn.og/simple-2.1.1-06b44bd.min.css">
    ```
    or
    ```
    <link rel="stylesheet" href="web3://0x4F53Eae17346d6c0f96215Af157c7F8e093E17F1:1simple-2.1.1-06b44bd.min.css">
    ```
   

### Name Syntax and Normalization

In the Linagee Name Registrar (LNR), the syntax of names is a critical element that ensures compatibility and consistency in the system. To maintain a well-structured and uniform approach to name registration, LNR follows specific guidelines:

1. **Domain Name Syntax**
   - Linagee domain names are denoted by the top level domain (TLD) ".og".
   
2. **Subdomains**
   - Linagee does not support subdomains at this time. Any periods (".") in a name will deem it non-normalized and will be restricted from the Resolver at the **contract level**. Any attempt to register names not exactly 32 bytes will throw an error.
   
3. **Name Length Limitation:**
   - Names registered with LNR are restricted to 32 bytes at the **contract level**. It is important to note that these names can take up the all 32 bytes. Any names less than 32 bytes must be right padded in order to be eligible for normalization.
	   - For example:
		   - Valid✅:
			   - string: linageenamesmustbeexactly32bytes.og
			   - bytecode: 0x6c696e616765656e616d65736d757374626565786163746c7933326279746573
			- Valid✅:
			   - string: shortlinageename.og
			   - bytecode: 0x73686f72746c696e616765656e616d6500000000000000000000000000000000
		   - Invalid❌
			   - string: shortlinageename.og
			   - bytecode: 0x73686f72746c696e616765656e616d65
			   
   - To convert between *bytes32* and *string* you must use the following methodology:
```
   // Converts a bytes32 value to a string
   
   // @param {string} _hex A hexadecimal string representation of a bytes32 value
   // @returns {string} The string representation of the bytes32 value
   
     bytes32ToString(_hex) {
    return this.ethers.utils.toUtf8String(this.ethers.utils.arrayify(_hex).filter(n => n != 0));
	  }
```
```
  // Converts a string to a bytes32 value
  
  // @param {string} _string The string to convert
  // @returns {string} The bytes32 value
  
    stringToBytes32(_string) {
    let result = this.ethers.utils.hexlify(this.ethers.utils.toUtf8Bytes(_string));
    while (result.length < 66) {
      result += '0';
    }
    if (result.length !== 66) {
      throw new Error("invalid web3 implicit bytes32");
    }
    return result;
	}
  ```
  - This can also more easily be accomplished using our npm package [@linagee/lnr-ethers](https://www.npmjs.com/package/@linagee/lnr-ethers).

4. **Normalization Standard (ENSIP-15):**
   - LNR adheres to the [ENSIP-15](https://docs.ens.domains/ens-improvement-proposals/ensip-15-normalization-standard) Normalization Standard, which defines a set of rules for normalizing names. This standard ensures that all registered names are treated consistently, minimizing potential ambiguities and conflicts. 
   - The ENSIP-15 Normalization Standard encompasses processes such as converting names to lowERCase, removing leading and trailing whitespace, and performing Unicode normalization. This normalization process guarantees that registered names are in their most standardized and compatible form for effective use within the Linagee Name Registrar ecosystem.
   - Note that *normalization* is enforced by javascript libraries, not by the contract. Linagee encourages normalization by only formally allowing normalized names to be resolved to addresses if using our website for domain name management.
   - Examples of both **normalized** and **non-normalized** names:
	   - Normalized✅:
		   - string: linagee🌎.og
		   - bytecode: 0x6c696e61676565f09f8c8e000000000000000000000000000000000000000000
	  - Not normalized❌:
	       - string: LinagEe🌎.og
		   - bytecode: 0x4c696e61674565f09f8c8e000000000000000000000000000000000000000000
	   - Not normalized❌:
		   - string: linagee🌎.og
		   - bytecode: 0x6c696e61676565f09f8c8e000000000000000000000000000000000000001a1a
	   - Not normalized❌:
		   - string: lina.gee.og
		   - bytecode: 0x6c696e612e676565000000000000000000000000000000000000000000000000



## Rationale

The integration of on-chain permanent domain names as both address mappings and CDNs aligns seamlessly with ERC-4804, offering a trustless mapping solution that not only enhances data permanence but also promotes decentralized content delivery, ensuring a robust and censorship-resistant infrastructure for the Ethereum ecosystem.

## Security Considerations

No security considerations were found.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).


# Appendix A: Registrar Implementation

*0x5564886ca2C518d1964E5FCea4f423b41Db9F561*
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
*0x6023E55814DC00F094386d4eb7e17Ce49ab1A190*

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


# Appendix C: Wrapper Address
*0x2Cc8342d7c8BFf5A213eb2cdE39DE9a59b3461A7*

# Appendix D: CDN Address
*0x4F53Eae17346d6c0f96215Af157c7F8e093E17F1*

# Appendix E: LNR-Web
*0xfeae5e7264A193B56A1d351052C0515eabe6a455*

The LNR-Web contract serves as an innovative addition to the Linagee Name Registrar ecosystem, enhancing the utility and versatility of Linagee names. This contract empowers users to upload data in the form of Ethereum Virtual Machine (EVM) calldata, enabling the creation of semi-permanent on-chain websites. This functionality is vividly demonstrated by **lnrforever.og**, highlighting how Linagee names can be used to point to evolving content stored in calldata, opening new possibilities for on-chain website development and content management.

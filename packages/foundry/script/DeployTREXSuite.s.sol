// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "./DeployHelpers.s.sol";
import { TREXFactory } from "../contracts/factory/TREXFactory.sol";
import { ITREXFactory } from "../contracts/factory/ITREXFactory.sol";
import { ImplementationAuthority } from "../lib/solidity/contracts/proxy/ImplementationAuthority.sol";
import { IdFactory } from "../lib/solidity/contracts/factory/IdFactory.sol";
import { TREXImplementationAuthority } from "../contracts/proxy/authority/TREXImplementationAuthority.sol";
import { ITREXImplementationAuthority } from "../contracts/proxy/authority/ITREXImplementationAuthority.sol";

import {Token} from "../contracts/token/Token.sol";
import {ClaimTopicsRegistry} from "../contracts/registry/implementation/ClaimTopicsRegistry.sol";
import "../lib/solidity/contracts/interface/IIdentity.sol";
import {IdentityRegistry} from "../contracts/registry/implementation/IdentityRegistry.sol";
import {IdentityRegistryStorage} from "../contracts/registry/implementation/IdentityRegistryStorage.sol";
import {TrustedIssuersRegistry} from "../contracts/registry/implementation/TrustedIssuersRegistry.sol";
import {ModularCompliance} from "../contracts/compliance/modular/ModularCompliance.sol";

import {TokenProxy} from "../contracts/proxy/TokenProxy.sol";
import {ClaimTopicsRegistryProxy} from "../contracts/proxy/ClaimTopicsRegistryProxy.sol";
import {IdentityRegistryProxy} from "../contracts/proxy/IdentityRegistryProxy.sol";
import {IdentityRegistryStorageProxy} from "../contracts/proxy/IdentityRegistryStorageProxy.sol";
import {TrustedIssuersRegistryProxy} from "../contracts/proxy/TrustedIssuersRegistryProxy.sol";
import {ModularComplianceProxy} from "../contracts/proxy/ModularComplianceProxy.sol";
import {DefaultCompliance} from "../contracts/compliance/legacy/DefaultCompliance.sol";

import {AgentManager} from "../contracts/roles/permissioning/agent/AgentManager.sol";

import {Identity} from "@onchain-id/solidity/contracts/Identity.sol";
import {IdentityProxy} from "../lib/solidity/contracts/proxy/IdentityProxy.sol";
import {IClaimIssuer} from "../lib/solidity/contracts/interface/IClaimIssuer.sol";

contract DeployTREXSuiteScript is Script {    
    struct trexContracts {
        Token tokenImplementation;
        ClaimTopicsRegistry claimTopicsRegistryImplementation;
        IdentityRegistry identityRegistryImplementation;
        IdentityRegistryStorage identityRegistryStorageImplementation;
        TrustedIssuersRegistry trustedIssuersRegistryImplementation;
        ModularCompliance modularComplianceImplementation;
    }    
    address implementationAuthority;
    address idFactory;
    IdentityRegistry ir;
    IdentityRegistryStorage irs;
    TrustedIssuersRegistry tir;
    address admin = vm.envAddress("ADMIN");

    // Deploys the TREX Suite
    function run() external {        
        vm.startBroadcast(admin);
        // Deploy the Implementation Authority
        implementationAuthority = deployImplementationAuthority();
        console.log("Implementation Authority deployed at:", implementationAuthority);
        // Deploy the IdFactory
        idFactory = deployIdFactory(implementationAuthority);
        console.log("IdFactory deployed at:", idFactory);
        // Deploy TREX suite
        deployFactory();
        console.log("TREXFactory deployed and set up with TREXImplementationAuthority");
        vm.stopBroadcast();
        
        // Register issuer in IdentityRegistry 
        address issuerOnchainIdentity = registerIssuerInIdentityRegistry();       
        // Add claim signing key to issuer identity       
        addClaimSigningKeytoIssuer(issuerOnchainIdentity);
        // Create user identity
        address userOnchainIdentity = createandRegisterUserIdentity();
        // Add claim to user identity        
        addClaimToUser(issuerOnchainIdentity,userOnchainIdentity);
        // Add trusted issuer to TrustedIssuersRegistry with claim topics
        uint256[] memory claimTopics = new uint256[](1);
        claimTopics[0] = 1; // Assuming claim topic 1 is used
        addTrustedIssuerToRegistry(issuerOnchainIdentity, claimTopics);
        // Mint tokens and add user as agent in TokenProxy
        mintTokens();
    }

    function mintTokens() internal {
        address tokenProxy = vm.envAddress("TOKEN_PROXY");
        uint256 claimIssuerPrivateKey = vm.envUint("ISSUER_PK");

        // uint256 userPrivateKey = vm.envUint("USER_PK");        
        vm.startBroadcast(claimIssuerPrivateKey);
        TokenProxy tokenProxyInstance = TokenProxy(payable(tokenProxy));
        // Update the token proxy to add the user as an agent
        Token token = Token(payable(tokenProxyInstance));
        // token.unpause();
        token.mint(vm.envAddress("USER_WALLET"), 1000 * 10 ** 18);
        // token.transfer(vm.envAddress("USER_WALLET"), 10 * 10 ** 18);
        console.log("balance",token.balanceOf(vm.envAddress("USER_WALLET")));
        
        // token.transfer(vm.envAddress("USER_WALLET"), 100 * 10 ** 18);
        // token.addAgent(vm.addr(claimIssuerPrivateKey));
        console.log("User added as agent in Token Proxy");
        vm.stopBroadcast();
    }

    // Deploys the Implementation Authority and returns its address
    function deployImplementationAuthority() internal returns(address) {
        Identity identity = new Identity(admin, true);
        ImplementationAuthority authority = new ImplementationAuthority(address(identity));
        console.log("Identity deployed at:", address(identity));        
        return address(authority);
    }
    // Deploys the IdFactory and returns its address
    function deployIdFactory(address idImplementationAuthority) internal returns(address) {
        return address(new IdFactory(idImplementationAuthority));        
    }
    // Deploys the TREXFactory and sets it up with the TREXImplementationAuthority
    function deployFactory() internal {        
        // Setup the TREXImplementationAuthority with the version and contracts
        // trexContracts memory contracts;
        Token tokenImplementation = new Token();        
        ClaimTopicsRegistry claimTopicsRegistryImplementation = new ClaimTopicsRegistry();
        IdentityRegistry identityRegistryImplementation = new IdentityRegistry();
        IdentityRegistryStorage identityRegistryStorageImplementation = new IdentityRegistryStorage();
        TrustedIssuersRegistry trustedIssuersRegistryImplementation = new TrustedIssuersRegistry();
        ModularCompliance modularComplianceImplementation = new ModularCompliance();

        ITREXImplementationAuthority.TREXContracts memory contractsStruct = ITREXImplementationAuthority.TREXContracts({
            tokenImplementation: address(tokenImplementation),
            ctrImplementation: address(claimTopicsRegistryImplementation),
            irImplementation: address(identityRegistryImplementation),
            irsImplementation: address(identityRegistryStorageImplementation),
            tirImplementation: address(trustedIssuersRegistryImplementation),
            mcImplementation: address(modularComplianceImplementation)
        });
        ITREXImplementationAuthority.Version memory versionStruct = ITREXImplementationAuthority.Version({
            major: 4,
            minor: 0,
            patch: 0
        });       
        TREXImplementationAuthority trexIAuthority = new TREXImplementationAuthority(true, address(0),address(0));
        trexIAuthority.addAndUseTREXVersion(versionStruct, contractsStruct);

        // Set TREXFactory 
        TREXFactory trexFactory = new TREXFactory(address(trexIAuthority), idFactory);
        trexIAuthority.setTREXFactory(address(trexFactory));
        IdFactory(idFactory).addTokenFactory(address(trexFactory));
        
        ModularComplianceProxy mcProxy = new ModularComplianceProxy(address(trexIAuthority));
        ModularCompliance mc = ModularCompliance(address(mcProxy));  
        ClaimTopicsRegistryProxy ctrProxy = new ClaimTopicsRegistryProxy(address(trexIAuthority));
        ClaimTopicsRegistry ctr = ClaimTopicsRegistry(address(ctrProxy));
        TrustedIssuersRegistryProxy tirProxy = new TrustedIssuersRegistryProxy(address(trexIAuthority));
        tir = TrustedIssuersRegistry(address(tirProxy));        
        IdentityRegistryStorageProxy irsProxy = new IdentityRegistryStorageProxy(address(trexIAuthority));
        irs = IdentityRegistryStorage(address(irsProxy));
        IdentityRegistryProxy irProxy = new IdentityRegistryProxy(
            address(trexIAuthority),
            address(tir),
            address(ctr),
            address(irs)
        );
        ir = IdentityRegistry(address(irProxy));             
        
        // Create IdentityProxy and Identity
        IdentityProxy identityProxy = new IdentityProxy(implementationAuthority,admin);
        Identity identity = Identity(address(identityProxy));      
       
        // Create TokenProxy and Token
        string memory tokenName = "Neo Token";
        string memory tokenSymbol = "NT";
        uint8 tokenDecimals = 8;
        TokenProxy tokenProxy = new TokenProxy(
            address(trexIAuthority), address(ir), address(mc), tokenName, tokenSymbol, tokenDecimals, address(0));
        Token token = Token(address(tokenProxy));
        console.log("Token deployed at:", address(token));
        
        // Setup agents
        AgentManager agentManager = new AgentManager(address(token));
        agentManager.addAgentAdmin(admin);

        irs.bindIdentityRegistry(address(ir));
        ir.addAgent(admin);
        irs.addAgent(admin);
        ir.addAgent(address(token));
        ir.addAgent(address(agentManager));

        token.addAgent(admin);       
        token.addAgent(address(agentManager));

         // Ensure that Issuer is added as an agent in IdentityRegistry, IdentityRegistryStorage, and TokenProxy
        ir.addAgent(vm.envAddress("ISSUER_WALLET"));
        irs.addAgent(vm.envAddress("ISSUER_WALLET"));
        token.addAgent(vm.envAddress("ISSUER_WALLET"));     

        // Add claim topic to ClaimTopicsRegistry
        ctr.addClaimTopic(1);
       
    }

    function registerIssuerInIdentityRegistry() internal returns (address) {
        address issuerWallet = vm.envAddress("ISSUER_WALLET");
        vm.startBroadcast(admin);
         // Create Onchain identity for Issuer and User accounts using IDFactory
        IdFactory idFactoryInstance = IdFactory(idFactory);
        address issuerOnchainIdentity = idFactoryInstance.createIdentity(issuerWallet, "Issuer Identity");
        ir.registerIdentity(issuerWallet, IIdentity(issuerOnchainIdentity), 0);      
        console.log("Issuer identity registered in IdentityRegistry");
        vm.stopBroadcast();
        return issuerOnchainIdentity;
    }

    function addClaimSigningKeytoIssuer(address claimIssuerOnchainIdentity) internal {
        uint256 claimIssuerPrivateKey = vm.envUint("ISSUER_PK");
        // Add claim signing key to issuer identity
        vm.startBroadcast(claimIssuerPrivateKey);      
        address claimSignerAddress = vm.addr(claimIssuerPrivateKey);
        bytes32 claimSignerKey = keccak256(abi.encode(claimSignerAddress));
        Identity issuerIdentity = Identity(payable(claimIssuerOnchainIdentity));        
        bool isClaimSigner;       
        console.log("Is Claim Issuer a claim signer?", isClaimSigner);
        uint256[] memory _purposes = issuerIdentity.getKeyPurposes(claimSignerKey);
        for (uint256 keyPurposeIndex = 0; keyPurposeIndex < _purposes.length; keyPurposeIndex++) {
            uint256 purpose = _purposes[keyPurposeIndex];
            if (purpose == 3) {
                console.log("Claim Signer Key already has purpose 3");
                isClaimSigner=true; // Claim signer key already has purpose 3
            }
           console.log("Key Purpose:", purpose);
        }
        if (!isClaimSigner) {            
            issuerIdentity.addKey(claimSignerKey, 3, 1);           
            console.log("Added issuerWallet as claim signer");
        }
        vm.stopBroadcast();
    }

    function createandRegisterUserIdentity() internal returns (address) {
        vm.startBroadcast(admin);
        IdFactory idFactoryInstance = IdFactory(idFactory);
        address userOnchainIdentity = idFactoryInstance.createIdentity(vm.envAddress("USER_WALLET"), "User Identity");
        ir.registerIdentity(
            vm.envAddress("USER_WALLET"),
            IIdentity(userOnchainIdentity),
            0 // Assuming 0 is the country code for this example
        );
        console.log("User identity added to IdentityRegistryStorage");
        vm.stopBroadcast();
        return userOnchainIdentity;
    }

    function addClaimToUser(address claimIssuerOnchainIdentity, address userOnchainIdentity) internal {       
        uint256 claimIssuerPrivateKey = vm.envUint("ISSUER_PK");        
        // Isser to produce signature for claim
        uint256 claimTopic = 1;
        uint256 scheme = 1;
        bytes memory claimData = abi.encode("KYC: YES");
        string memory uri = "";
        
        bytes32 claimHash = keccak256(abi.encode(
            userOnchainIdentity,
            claimTopic,
            claimData
        ));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vm.addr(claimIssuerPrivateKey), ethSigned);
        bytes memory signature = abi.encodePacked(r, s, v);

        // User to add claim using issuer signature
        uint256 userPrivateKey = vm.envUint("USER_PK");    
        vm.startBroadcast(userPrivateKey);
        Identity userIdentity = Identity(payable(userOnchainIdentity));
        userIdentity.addClaim(claimTopic, scheme, claimIssuerOnchainIdentity, signature, claimData, uri);
        console.log("Claim added to user identity");
        vm.stopBroadcast();
        
    }

    function addTrustedIssuerToRegistry(
        address claimIssuerOnchainIdentity,
        uint256[] memory claimTopics
    ) internal {
        vm.startBroadcast(admin);
        // Add trusted issuer to TrustedIssuersRegistry with claim topics
        tir.addTrustedIssuer(
            IClaimIssuer(claimIssuerOnchainIdentity), // Issuer wallet address
            claimTopics // Claim topics for the issuer
        );
        console.log("Trusted Issuer added to TrustedIssuersRegistry with claim topics");
        vm.stopBroadcast();
    }   
}
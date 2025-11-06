// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableNFT
 * @notice Test contract for ERC-721 and ERC-1155 vulnerabilities
 *
 * DETECTORS TO TEST:
 * - erc721-callback-reentrancy (High)
 * - erc721-enumeration-dos (Medium)
 * - erc1155-batch-validation (Medium)
 * - flashmint-token-inflation (High)
 * - erc7821-token-approval (Critical)
 *
 * VULNERABILITIES:
 * 1. ERC-721 callback reentrancy
 * 2. ERC-721 enumeration DOS
 * 3. ERC-1155 batch validation bypass
 * 4. Flash minting for NFT manipulation
 * 5. Unsafe minting
 * 6. Missing ownership validation
 */

/**
 * @notice Vulnerable ERC-721 with callback reentrancy
 */
contract VulnerableERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;

    uint256 public totalSupply;
    uint256 public nextTokenId = 1;

    // ❌ VULNERABILITY 1: Reentrancy via onERC721Received callback (erc721-callback-reentrancy)
    function mint(address to) external {
        uint256 tokenId = nextTokenId++;

        ownerOf[tokenId] = to;
        balanceOf[to]++;
        totalSupply++;

        // ❌ External call BEFORE state is finalized!
        // ❌ Allows reentrancy attacks!

        if (to.code.length > 0) {
            // ❌ Calls user contract with incomplete state!
            try IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "") returns (bytes4 response) {
                require(response == IERC721Receiver.onERC721Received.selector, "Invalid receiver");
            } catch {
                revert("Transfer to non-receiver");
            }
        }

        // Attack scenario:
        // 1. Attacker contract calls mint()
        // 2. mint() transfers NFT to attacker
        // 3. onERC721Received hook is called
        // 4. In hook, attacker calls mint() again (reentrancy!)
        // 5. Since totalSupply not yet updated, attacker can bypass limits
        // 6. Or attacker can manipulate other state
    }

    // ❌ VULNERABILITY 2: safeTransferFrom with reentrancy
    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "Not owner");
        require(msg.sender == from || getApproved[tokenId] == msg.sender, "Not authorized");

        // ❌ State changes
        ownerOf[tokenId] = to;
        balanceOf[from]--;
        balanceOf[to]++;
        delete getApproved[tokenId];

        // ❌ External call after state change (still allows reentrancy)
        if (to.code.length > 0) {
            IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "");

            // In callback, attacker can:
            // 1. Transfer NFT to another address
            // 2. List NFT on marketplace
            // 3. Borrow against NFT as collateral
            // 4. Vote with NFT in governance
            // All while safeTransferFrom is still executing!
        }
    }

    function approve(address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender, "Not owner");
        getApproved[tokenId] = to;
    }
}

/**
 * @notice ERC-721 with enumeration DOS vulnerability
 */
contract VulnerableERC721Enumeration {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256[]) public tokensOwned;

    uint256 public nextTokenId = 1;

    // ❌ VULNERABILITY 3: Unbounded array iteration (erc721-enumeration-dos)
    function mint(address to) external {
        uint256 tokenId = nextTokenId++;
        ownerOf[tokenId] = to;

        // ❌ Adds to unbounded array!
        tokensOwned[to].push(tokenId);

        // After user owns 1000+ NFTs, any function iterating this array will run out of gas!
    }

    // ❌ VULNERABILITY 4: O(n) transfer operation
    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from);

        ownerOf[tokenId] = to;

        // ❌ Must find and remove tokenId from from's array!
        // ❌ O(n) operation - expensive for users with many NFTs!
        uint256[] storage fromTokens = tokensOwned[from];
        for (uint256 i = 0; i < fromTokens.length; i++) {
            if (fromTokens[i] == tokenId) {
                // Swap with last element and pop
                fromTokens[i] = fromTokens[fromTokens.length - 1];
                fromTokens.pop();
                break;
            }
        }

        // ❌ Then add to recipient's array
        tokensOwned[to].push(tokenId);

        // Attack:
        // 1. Attacker accumulates 10,000 NFTs
        // 2. Transfers create DOS (runs out of gas)
        // 3. NFTs become untransferable
        // 4. User can't sell, can't use in protocols
    }

    // ❌ VULNERABILITY 5: Enumeration query DOS
    function tokensOfOwner(address owner) external view returns (uint256[] memory) {
        // ❌ Returns entire array - can be 10,000+ items!
        // ❌ View function can run out of gas!
        // ❌ Breaks integrations with wallets, marketplaces!
        return tokensOwned[owner];
    }
}

/**
 * @notice Vulnerable ERC-1155 multi-token
 */
contract VulnerableERC1155 {
    mapping(uint256 => mapping(address => uint256)) public balanceOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    // ❌ VULNERABILITY 6: Missing batch validation (erc1155-batch-validation)
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external {
        require(from == msg.sender || isApprovedForAll[from][msg.sender], "Not authorized");

        // ❌ No validation that ids.length == amounts.length!
        // ❌ If lengths mismatch, can cause out-of-bounds access!

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i]; // ❌ Can panic if i >= amounts.length!

            require(balanceOf[id][from] >= amount, "Insufficient balance");

            balanceOf[id][from] -= amount;
            balanceOf[id][to] += amount;
        }

        // ❌ Calls onERC1155BatchReceived without validating response!
        if (to.code.length > 0) {
            IERC1155Receiver(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data);
        }
    }

    // ❌ VULNERABILITY 7: No validation of return value from hook
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external {
        require(balanceOf[id][from] >= amount);

        balanceOf[id][from] -= amount;
        balanceOf[id][to] += amount;

        if (to.code.length > 0) {
            // ❌ Doesn't check return value!
            // ❌ Receiver can return anything (or revert) but transfer still succeeds!
            try IERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, data) returns (bytes4) {
                // No validation of return value
            } catch {
                // Ignores revert!
            }
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }
}

/**
 * @notice NFT with flash mint vulnerability
 */
contract VulnerableNFTFlashMint {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;

    uint256 public nextTokenId = 1;

    // ❌ VULNERABILITY 8: Flash minting NFTs (flashmint-token-inflation)
    function flashMint(address to, uint256[] calldata tokenIds, bytes calldata data) external {
        // ❌ Mints NFTs temporarily for use in callback!
        // ❌ Can be exploited for:
        // 1. Governance manipulation (vote with borrowed NFTs)
        // 2. Airdrop farming (claim with flash-minted NFTs)
        // 3. Marketplace manipulation
        // 4. Snapshot gaming

        // Mint NFTs
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            ownerOf[tokenId] = to;
            balanceOf[to]++;
        }

        // ❌ Give control to user with minted NFTs!
        IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenIds[0], data);

        // Burn NFTs
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            require(ownerOf[tokenId] == to, "NFT transferred");
            delete ownerOf[tokenId];
            balanceOf[to]--;
        }

        // Attack:
        // 1. Flash mint 1000 NFTs
        // 2. In callback, vote in governance proposal
        // 3. Proposal passes with flash-minted voting power
        // 4. NFTs burned, but vote persists
    }
}

/**
 * @notice NFT marketplace with approval vulnerabilities
 */
contract VulnerableNFTMarketplace {
    struct Listing {
        address seller;
        uint256 price;
        bool active;
    }

    mapping(uint256 => Listing) public listings;
    IERC721 public nftContract;

    constructor(address _nftContract) {
        nftContract = IERC721(_nftContract);
    }

    // ❌ VULNERABILITY 9: Doesn't validate NFT approval (erc7821-token-approval)
    function listNFT(uint256 tokenId, uint256 price) external {
        // ❌ No check that seller owns the NFT!
        // ❌ No check that marketplace is approved!

        listings[tokenId] = Listing({
            seller: msg.sender,
            price: price,
            active: true
        });

        // Issues:
        // 1. User can list NFTs they don't own
        // 2. User can list without approval
        // 3. Buyer purchases, transaction fails
        // 4. Or worse: listing remains, seller transfers NFT, buyer unknowingly buys nothing
    }

    // ❌ VULNERABILITY 10: Doesn't re-validate approval before transfer
    function buyNFT(uint256 tokenId) external payable {
        Listing memory listing = listings[tokenId];
        require(listing.active, "Not listed");
        require(msg.value >= listing.price, "Insufficient payment");

        listings[tokenId].active = false;

        // ❌ No check if seller still owns NFT!
        // ❌ No check if marketplace still has approval!
        // ❌ NFT could have been transferred or approval revoked!

        nftContract.transferFrom(listing.seller, msg.sender, tokenId);

        payable(listing.seller).transfer(listing.price);
    }

    // ❌ VULNERABILITY 11: Doesn't handle approval revocation
    function updatePrice(uint256 tokenId, uint256 newPrice) external {
        Listing storage listing = listings[tokenId];
        require(listing.seller == msg.sender, "Not seller");

        // ❌ No check if seller still owns NFT!
        // ❌ Seller could have transferred NFT but listing remains!

        listing.price = newPrice;
    }
}

/**
 * @notice Lending protocol using NFTs as collateral
 */
contract VulnerableNFTLending {
    struct Loan {
        address borrower;
        uint256 nftId;
        uint256 loanAmount;
        uint256 startTime;
    }

    mapping(uint256 => Loan) public loans;
    IERC721 public nftContract;

    constructor(address _nftContract) {
        nftContract = IERC721(_nftContract);
    }

    // ❌ VULNERABILITY 12: Accepts NFT as collateral without validation
    function borrow(uint256 nftId, uint256 amount) external {
        // ❌ No validation that NFT exists!
        // ❌ No validation of NFT ownership!
        // ❌ No oracle for NFT value!

        // Transfer NFT to contract
        nftContract.transferFrom(msg.sender, address(this), nftId);

        loans[nftId] = Loan({
            borrower: msg.sender,
            nftId: nftId,
            loanAmount: amount,
            startTime: block.timestamp
        });

        // ❌ Lends based on arbitrary amount without checking NFT value!
        payable(msg.sender).transfer(amount);

        // Attack:
        // 1. Create worthless NFT
        // 2. Use as collateral for large loan
        // 3. Never repay loan
        // 4. Protocol left with worthless NFT
    }

    function repay(uint256 nftId) external payable {
        Loan memory loan = loans[nftId];
        require(loan.borrower == msg.sender, "Not borrower");
        require(msg.value >= loan.loanAmount, "Insufficient repayment");

        delete loans[nftId];

        nftContract.transferFrom(address(this), msg.sender, nftId);
    }
}

// Interfaces
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
}

interface IERC1155Receiver {
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

/**
 * @notice Secure NFT implementations
 */
contract SecureERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;

    uint256 private _reentrancyLock;

    modifier nonReentrant() {
        require(_reentrancyLock == 0, "Reentrant call");
        _reentrancyLock = 1;
        _;
        _reentrancyLock = 0;
    }

    // ✅ Secure mint with reentrancy guard
    function safeMint(address to, uint256 tokenId) external nonReentrant {
        require(ownerOf[tokenId] == address(0), "Already minted");

        // ✅ State changes first
        ownerOf[tokenId] = to;
        balanceOf[to]++;

        // ✅ External call last, with reentrancy protection
        if (to.code.length > 0) {
            require(
                IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "") ==
                    IERC721Receiver.onERC721Received.selector,
                "Invalid receiver"
            );
        }
    }
}

contract SecureERC1155 {
    // ✅ Validate batch array lengths
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external {
        // ✅ Validate array lengths match
        require(ids.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < ids.length; i++) {
            // Transfer logic
        }

        // ✅ Validate return value
        if (to.code.length > 0) {
            require(
                IERC1155Receiver(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data) ==
                    IERC1155Receiver.onERC1155BatchReceived.selector,
                "Invalid receiver"
            );
        }
    }
}

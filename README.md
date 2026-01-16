# Complete Security Audit Guide for Prediction Markets
---
> Languages: [English](README.md) | [Chinese](README_CN.md)

> Full-Stack Checklist Based on Real Security Incidents from Polymarket, Kalshi, opinionlabsxyz, Augur, and Other Platforms

## Preface

Prediction markets experienced explosive growth in 2024-2025, with Polymarket's monthly trading volume exceeding $3 billion and active users surpassing 400,000. However, this growth came with a series of security incidents: from the $230,000 theft from the Polycule bot, to the $7 million manipulation attack on UMA oracle, to the $500,000 loss from comment section phishing.

This guide is based on real security incidents in prediction markets, providing a complete security checklist. Each item includes: risk description, severity assessment, real-world case study, and remediation recommendations.

---

## Table of Contents

1. [Third-Party Authentication Security](#i-third-party-authentication-security)
2. [Oracle and Resolution Security](#ii-oracle-and-resolution-security)
3. [Trading Bot Security](#iii-trading-bot-security)
4. [Social Engineering and Phishing Prevention](#iv-social-engineering-and-phishing-prevention)
5. [Smart Contract Security](#v-smart-contract-security)
6. [Cross-Chain Bridge Security](#vi-cross-chain-bridge-security)
7. [Copy Trading Security](#vii-copy-trading-security)
8. [Client-Side Security](#viii-client-side-security)
9. [Operations and Incident Response](#ix-operations-and-incident-response)

---

## I. Third-Party Authentication Security

### 1.1 Third-Party Authentication Provider Vulnerabilities

| Item | Content |
|-----|------|
| **Check Item** | Whether third-party authentication services (e.g., Magic Labs) have known vulnerabilities |
| **Status** | ☐ Pending Review |

**Risk Description**

To lower the barrier to entry for users, prediction markets often integrate third-party authentication services (such as Magic Labs) that allow users to log in via email and automatically create non-custodial wallets. However, these third-party services may introduce security vulnerabilities beyond the platform's direct control.

**Severity**: 🔴 **Critical** — Batch account takeover, funds stolen

**Real-World Case: Polymarket Magic Labs Authentication Vulnerability (December 2024)**

```
Incident Date: December 22-24, 2024
Affected Scope: Users logging in via Magic Labs email
Attack Process:
1. Attackers discovered a vulnerability in the Magic Labs authentication system
2. Users reported receiving unusual login attempt notifications
3. Subsequently, account balances were drained and positions were force-closed
4. Some users reported that OTP codes at the time were only 3 digits, making them vulnerable to brute force attacks

User Testimony (Reddit):
"Woke up today to find 3 login attempts. My device wasn't compromised, Google found nothing unusual,
all other services were fine. Logged into Polymarket to find all trades closed, balance only $0.01."

Aftermath: Polymarket increased OTP length from 3 to 6 digits
```

**Remediation Recommendations**

```python
# ✅ Multi-layer authentication verification architecture
class SecureAuthProvider:
    def __init__(self):
        self.primary_auth = MagicLabsAuth()
        self.secondary_checks = []
    
    async def authenticate(self, user_request) -> AuthResult:
        # 1. Third-party authentication
        primary_result = await self.primary_auth.verify(user_request)
        if not primary_result.success:
            return AuthResult(success=False)
        
        # 2. Device fingerprint verification
        device_check = self.verify_device_fingerprint(
            user_request.device_info,
            user_request.user_id
        )
        if not device_check.is_known_device:
            # New device requires additional verification
            await self.send_new_device_alert(user_request.user_id)
            return AuthResult(success=False, requires_additional_verification=True)
        
        # 3. Behavioral analysis
        if self.detect_anomalous_login_pattern(user_request):
            await self.trigger_security_review(user_request)
            return AuthResult(success=False, requires_manual_review=True)
        
        # 4. Geographic consistency check
        if not self.verify_geo_consistency(user_request):
            await self.send_location_change_alert(user_request.user_id)
        
        return AuthResult(success=True)
    
    def detect_anomalous_login_pattern(self, request) -> bool:
        """Detect anomalous login patterns"""
        recent_attempts = self.get_recent_login_attempts(request.user_id, hours=24)
        
        # Multiple attempts in short time
        if len(recent_attempts) > 5:
            return True
        
        # Rapid IP address changes
        unique_ips = set(a.ip for a in recent_attempts)
        if len(unique_ips) > 3:
            return True
        
        return False
```


- **Third-Party Authentication Service Security Assessment Checklist**

| Assessment Item                                | Status  | Notes          |
|----------------------------------------------|------|---------------|
| Is OTP length >= 6 digits                    |  ☐   |               |
| Does OTP have attempt rate limiting          |  ☐   | Recommend 5 per hour |
| Does OTP have time expiration                |  ☐   | Recommend 5 minutes    |
| Does it support device binding               |  ☐   |               |
| Does it have anomalous login detection       |  ☐   |               |
| Does the provider have a security audit report |  ☐   |               |
| Provider's historical security incident record |  ☐   |               |
| Is there a backup authentication method      |  ☐   |               |



---

### 1.2 OAuth/Social Login Security

| Item | Content |
|-----|------|
| **Check Item** | Whether Google/social login has additional security protections |
| **Status** | ☐ Pending Review |

**Risk Description**

For users logging in via Google or other social accounts, their wallet security is directly tied to their social account security. If the platform's OAuth implementation has flaws, attackers could transfer user funds through proxy function calls.

**Severity**: 🔴 **Critical** — Bypassing user authorization to transfer funds

**Real-World Case: Polymarket Google Account Proxy Attack (September 2024)**

```
Incident Date: September 2024
Affected Scope: Users logging in via Google account
Attack Method:
1. Attackers exploited a proxy function call vulnerability
2. Initiated USDC transfers without user knowledge
3. Funds were transferred to addresses marked as "Fake_Phishing"
4. Mainly affected Google login users; MetaMask/TrustWallet users were unaffected

Technical Details:
- The attack exploited the authorization mechanism of wallet proxy contracts
- Permissions granted by users during login were abused
- Transactions were executed via proxy functions, bypassing normal confirmation flows
```

**Remediation Recommendations**

```solidity
// ✅ Secure proxy wallet design
contract SecureProxyWallet {
    mapping(address => bool) public authorizedCallers;
    mapping(bytes4 => bool) public allowedFunctions;
    mapping(address => uint256) public dailyLimit;
    mapping(address => uint256) public dailySpent;
    mapping(address => uint256) public lastResetDay;
    
    // Whitelisted function selectors
    bytes4 constant PLACE_BET_SELECTOR = bytes4(keccak256("placeBet(uint256,bool,uint256)"));
    bytes4 constant CLAIM_WINNINGS_SELECTOR = bytes4(keccak256("claimWinnings(uint256)"));
    
    constructor() {
        // Only allow specific functions
        allowedFunctions[PLACE_BET_SELECTOR] = true;
        allowedFunctions[CLAIM_WINNINGS_SELECTOR] = true;
        // Note: Do not allow arbitrary transfer or approve
    }
    
    function execute(
        address target,
        bytes calldata data,
        uint256 value
    ) external returns (bytes memory) {
        // 1. Caller verification
        require(authorizedCallers[msg.sender], "Unauthorized caller");
        
        // 2. Function selector whitelist
        bytes4 selector = bytes4(data[:4]);
        require(allowedFunctions[selector], "Function not allowed");
        
        // 3. Target contract whitelist
        require(isWhitelistedTarget(target), "Target not whitelisted");
        
        // 4. Daily limit check
        _checkAndUpdateDailyLimit(msg.sender, value);
        
        // 5. Execute call
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Call failed");
        
        emit ProxyExecution(msg.sender, target, selector, value);
        return result;
    }
    
    function _checkAndUpdateDailyLimit(address user, uint256 amount) internal {
        uint256 today = block.timestamp / 1 days;
        
        if (lastResetDay[user] < today) {
            dailySpent[user] = 0;
            lastResetDay[user] = today;
        }
        
        require(dailySpent[user] + amount <= dailyLimit[user], "Daily limit exceeded");
        dailySpent[user] += amount;
    }
}
```

---

## II. Oracle and Resolution Security

### 2.1 Oracle Voting Power Concentration Risk

| Item | Content |
|-----|------|
| **Check Item** | Whether oracle voting power is excessively concentrated among a few holders |
| **Status** | ☐ Pending Review |

**Risk Description**

Prediction markets rely on oracles (such as UMA) to resolve market outcomes. If oracle tokens are highly concentrated among a few "whales," they can manipulate market resolutions through voting power to gain illicit profits.

**Severity**: 🔴 **Critical** — Market outcomes are maliciously manipulated, users suffer significant losses

**Real-World Case: Polymarket UMA Oracle Manipulation Attack (March 2025)**

```
Incident Date: March 24-25, 2025
Affected Market: "Will Ukraine agree to Trump's mineral deal before April?"
Amount Involved: Approximately $7 million

Attack Process:
1. The market originally showed "Yes" probability at only 9%
2. The attacker (UMA whale) held approximately 5 million UMA tokens
3. Voted through 3 accounts, accounting for 25% of total voting power
4. Forcibly resolved the market to "Yes"
5. Market jumped from 9% to 100% instantly

Key Facts:
- At the time of resolution, Ukraine had not formally signed any agreement
- Trump only stated "expected to sign soon"
- Polymarket officially stated the resolution was premature
- However, UMA voting results are final and cannot be overturned

Attacker's Profit: Estimated millions of dollars
User Losses: All holders of "No" positions were zeroed out

Polymarket Response:
"This is an unprecedented situation, we are urgently discussing with the UMA team to prevent such incidents from happening again."
```

**Subsequent Impact**

```
UMA Follow-up Measures (November 2025):
- Restricted market resolution proposal rights to 37 pre-approved addresses
- Including Risk Labs employees, high-accuracy users, etc.
- Critics argue this increases centralization risk

Voting Power Concentration Data:
- According to analysis, only 2 large holders control more than 50% of UMA voting power
- 95% of UMA tokens are held by large holders
```

**Remediation Recommendations**

```solidity
// ✅ Manipulation-resistant oracle design
contract ManipulationResistantOracle {
    uint256 public constant MIN_VOTE_PARTICIPATION = 30;  // Minimum 30% participation rate
    uint256 public constant MAX_SINGLE_VOTER_WEIGHT = 5;  // Maximum 5% weight per voter
    uint256 public constant DISPUTE_PERIOD = 48 hours;
    uint256 public constant VOTE_LOCK_PERIOD = 7 days;    // Lock period after voting
    
    struct Market {
        bytes32 id;
        uint8 proposedOutcome;
        uint256 proposedAt;
        uint256 totalValueLocked;
        mapping(address => uint256) votes;
        mapping(uint8 => uint256) outcomeVotes;
    }
    
    mapping(address => uint256) public voterLockUntil;
    
    function vote(bytes32 marketId, uint8 outcome) external {
        Market storage market = markets[marketId];
        uint256 voterBalance = token.balanceOf(msg.sender);
        uint256 totalSupply = token.totalSupply();
        
        // 1. Single voter weight cap
        uint256 maxVotes = totalSupply * MAX_SINGLE_VOTER_WEIGHT / 100;
        uint256 effectiveVotes = voterBalance > maxVotes ? maxVotes : voterBalance;
        
        // 2. Record vote
        market.votes[msg.sender] = effectiveVotes;
        market.outcomeVotes[outcome] += effectiveVotes;
        
        // 3. Lock voter tokens (prevent immediate sell after voting)
        voterLockUntil[msg.sender] = block.timestamp + VOTE_LOCK_PERIOD;
        
        emit VoteCast(marketId, msg.sender, outcome, effectiveVotes);
    }
    
    function finalizeMarket(bytes32 marketId) external {
        Market storage market = markets[marketId];
        
        // 1. Ensure dispute period has passed
        require(
            block.timestamp >= market.proposedAt + DISPUTE_PERIOD,
            "Dispute period active"
        );
        
        // 2. Check minimum participation rate
        uint256 totalVotes = getTotalVotes(marketId);
        uint256 totalSupply = token.totalSupply();
        require(
            totalVotes * 100 / totalSupply >= MIN_VOTE_PARTICIPATION,
            "Insufficient vote participation"
        );
        
        // 3. Check voting result clarity (requires over 60% support)
        uint8 winningOutcome = getLeadingOutcome(marketId);
        uint256 winningVotes = market.outcomeVotes[winningOutcome];
        require(
            winningVotes * 100 / totalVotes >= 60,
            "No clear majority"
        );
        
        // 4. High-value markets require higher threshold
        if (market.totalValueLocked > HIGH_VALUE_THRESHOLD) {
            require(
                winningVotes * 100 / totalVotes >= 75,
                "High-value market requires supermajority"
            );
        }
        
        _settleMarket(marketId, winningOutcome);
    }
}
```


- **Oracle Security Assessment Key Points:**

| Assessment Item                              | Recommended Threshold  | Status    |
|--------------------------------------------|----------|--------|
| Top 10 holders' voting power share          |  < 50%   |   ☐    |
| Maximum weight cap for single voter         |  < 5%    |   ☐    |
| Minimum vote participation requirement      |  > 30%   |   ☐    |
| Dispute period length                       | >= 48h   |   ☐    |
| Additional protection for high-value markets|   Yes    |   ☐    |
| Post-vote lock period                       |   Yes    |   ☐    |
| Multi-oracle cross-verification             |   Yes    |   ☐    |



---

### 2.2 Market Rule Ambiguity Risk

| Item | Content |
|-----|------|
| **Check Item** | Whether market resolution rules are clear and unambiguous |
| **Status** | ☐ Pending Review |

**Risk Description**

Prediction market outcome resolution depends on clear market rules. If rules are ambiguous, it may lead to resolution disputes, affecting user rights and platform reputation.

**Severity**: 🟠 **High** — Causes resolution disputes, damages user trust

**Real-World Case: Polymarket Trump Conviction Market Dispute (2024)**

```
Background:
Market Question: "Will Trump be convicted before [date]?"

Points of Dispute:
- Jury verdict (Guilty verdict)
- Formal sentencing by judge
These are different stages legally

Issues:
- Market rules did not clearly define what "conviction" specifically meant
- Some users believed jury verdict constituted conviction
- Other users believed formal sentencing by judge was required
- Resulted in widespread user dissatisfaction with the resolution

Lessons:
- Markets involving complex domains like law and politics need precise term definitions
- Need to cite authoritative information sources as resolution basis
- Should clarify all boundary conditions when creating the market
```

**Remediation Recommendations**

```solidity
// ✅ Structured market rule definition
contract StructuredMarket {
    struct MarketRules {
        string question;                    // Core question
        string[] resolutionCriteria;        // Resolution criteria list
        string[] authoritativeSources;      // Authoritative information sources
        string invalidConditions;           // Invalid conditions description
        uint256 minResolutionDelay;         // Minimum waiting time after event occurs
        bool requiresMultipleSources;       // Whether multiple source verification is required
    }
    
    function createMarket(
        MarketRules calldata rules,
        uint256 endTime
    ) external returns (uint256 marketId) {
        // 1. Rule completeness check
        require(bytes(rules.question).length >= 20, "Question too short");
        require(rules.resolutionCriteria.length >= 1, "Need resolution criteria");
        require(rules.authoritativeSources.length >= 1, "Need authoritative sources");
        
        // 2. Stricter requirements for high-value markets
        if (msg.value > HIGH_VALUE_THRESHOLD) {
            require(
                rules.authoritativeSources.length >= 2,
                "High-value markets need multiple sources"
            );
            require(rules.requiresMultipleSources, "Must require multiple sources");
        }
        
        // 3. Store and create market
        marketId = _createMarket(rules, endTime, msg.value);
        
        emit MarketCreated(marketId, rules.question, rules.resolutionCriteria);
    }
}

/*
Market Rules Template Example:

Question: Will Ukraine sign a mineral agreement with the US before April 1, 2025?

Resolution Criteria (all must be met):
1. Both parties formally sign a written agreement document
2. Agreement content involves mineral resource development or trading
3. Agreement is officially announced through both parties' official channels

Authoritative Sources:
1. Ukrainian government official website
2. US State Department official statement
3. Confirmation reports from major news agencies like Reuters/AP

Invalid Conditions:
- Verbal commitments or letters of intent alone do not count as signing
- Announcement by only one party without confirmation from the other does not count
- Draft or negotiating agreements do not count as signed

Minimum Waiting Time: 24 hours after event occurs
*/
```

---

## III. Trading Bot Security

### 3.1 Private Key Custody Risk

| Item | Content |
|-----|------|
| **Check Item** | Whether the trading bot securely manages user private keys |
| **Status** | ☐ Pending Review |

**Risk Description**

To provide convenient user experience, Telegram trading bots typically generate and custody private keys on the server side. This architecture centralizes all user private keys, creating a high-value attack target.

**Severity**: 🔴 **Critical** — All user funds can be stolen at once

**Real-World Case: Polycule Bot Attack (January 2026)**

```
Incident Date: January 7-13, 2026
Affected Project: Polycule (Top Telegram trading bot for Polymarket)
Loss Amount: Approximately $230,000
Investment Background: Had received $560,000 investment from AllianceDAO

Attack Process:
1. Attackers compromised Polycule backend servers
2. Obtained stored user private key data
3. Batch transferred user funds
4. Bot was forced offline

Polycule Feature Analysis (Exposed Risk Points):
- /start: Auto-generates Polygon wallet and custodies private key ← Centralized private key storage
- /wallet: Supports private key export ← Indicates backend stores reversible keys
- /buy, /sell: Backend signs transactions ← No user confirmation step
- /copytrade: Auto copy trading ← Long-term online signing

Team Response:
- Bot immediately went offline
- Committed to compensating affected users
- Planned security audit

Subsequent Developments:
- As of January 12, team went silent, no updates
- Competitors began claiming Polycule was a "rug pull"
- Users still unable to withdraw funds
```

**Remediation Recommendations**

```python
# ✅ Secure bot architecture design

# Option 1: Non-custodial architecture (Recommended)
class NonCustodialBot:
    """
    Users manage their own private keys, bot only builds transactions
    Users sign via external wallet
    """
    async def place_bet(self, user_id: str, market_id: str, amount: float):
        # 1. Build unsigned transaction
        unsigned_tx = self.build_transaction(market_id, amount)
        
        # 2. Generate transaction link, guide user to sign in external wallet
        signing_url = self.generate_walletconnect_url(unsigned_tx)
        
        # 3. Send to user for confirmation
        await self.send_message(user_id, f"""
🔐 Please confirm transaction in your wallet:

Market: {market_id}
Amount: {amount} USDC
Gas: Approximately {unsigned_tx.gas_estimate}

Click link to sign in wallet: {signing_url}

⚠️ We do not custody your private keys
        """)

# Option 2: MPC sharded custody
class MPCBot:
    """
    Private key stored in shards, signing requires multiple parties
    """
    def __init__(self):
        self.threshold = 2  # 2-of-3 threshold
        self.shard_servers = [
            'shard1.secure.internal',
            'shard2.secure.internal', 
            'shard3.secure.internal'  # Geographically isolated
        ]
    
    async def create_wallet(self, user_id: str) -> str:
        # Generate key shards
        shards = generate_key_shards(threshold=2, total=3)
        
        # Distributed storage (each server only has one shard)
        for server, shard in zip(self.shard_servers, shards):
            await self.store_shard_encrypted(server, user_id, shard)
        
        # No complete private key retained locally
        return derive_address_from_public_key(shards)
    
    async def sign_transaction(self, user_id: str, tx: Transaction):
        # 1. User confirmation
        confirmed = await self.request_user_confirmation(user_id, tx)
        if not confirmed:
            raise UserCancelled()
        
        # 2. Collect enough shards (requires 2 servers to participate)
        shards = []
        for server in self.shard_servers[:2]:
            shard = await self.request_shard(server, user_id, tx.hash())
            shards.append(shard)
        
        # 3. MPC signing (private key never appears complete)
        signature = mpc_sign(shards, tx.hash())
        return signature

# Option 3: If custody is necessary, use HSM
class HSMBackedBot:
    """
    Private keys stored in hardware security module, never exported
    """
    def __init__(self):
        self.hsm = CloudHSM(key_id=os.environ['HSM_KEY_ID'])
    
    async def create_wallet(self, user_id: str) -> str:
        # Generate key pair inside HSM
        key_handle = await self.hsm.generate_key(
            user_id=user_id,
            exportable=False  # Key: Not exportable
        )
        return await self.hsm.get_public_key(key_handle)
    
    async def sign_transaction(self, user_id: str, tx: Transaction):
        # Signing completed inside HSM, private key never leaves hardware
        return await self.hsm.sign(user_id, tx.hash())
```


- **Trading Bot Security Architecture Comparison:**

| Architecture Type          | Security | User Experience | Implementation Complexity | Recommendation  |
|------------------|-------|---------|----------|--------|
| Plaintext Custody          |  🔴    |   ⭐⭐⭐  |    Low   |  ❌    |
| Encrypted Custody (Static Key)|  🟠    |   ⭐⭐⭐  |    Low   | ❌    |
| HSM Custody          |  🟢    |   ⭐⭐⭐  |    Medium  |  ✅    |
| MPC Sharding          |  🟢    |   ⭐⭐    |    High | ✅    |
| Non-Custodial (WalletConnect)| 🟢  |   ⭐⭐   |    Medium | ✅    |



---

### 3.2 Private Key Export Interface Risk

| Item | Content |
|-----|------|
| **Check Item** | Whether private key export functionality has sufficient security protection |
| **Status** | ☐ Pending Review |

**Risk Description**

Providing private key export functionality means the backend must store private keys in reversible form, significantly increasing leakage risk. If the export interface has vulnerabilities, attackers can batch extract all user private keys.

**Severity**: 🔴 **Critical** — Batch private key leakage

**Real-World Case Analysis: Polycule Private Key Export Interface**

```
Polycule's /wallet command provided private key export functionality, which means:

1. Backend Storage Form:
   - Private keys must be stored in reversible form (plaintext or decryptable)
   - Cannot use one-way hashing

2. Potential Attack Vectors:
   a) SQL injection to obtain encrypted private keys + encryption key
   b) Unauthorized API access to export interface
   c) IDOR vulnerability accessing other users' private keys
   d) Private key leakage in logs
   e) Backup file leakage

3. Once attackers obtain:
   - Can batch decrypt offline
   - Transfer all user funds at once
   - Platform cannot prevent (on-chain transactions are irreversible)
```

**Remediation Recommendations**

```python
# ❌ Dangerous Design: Do not provide private key export
class DangerousBot:
    def export_key(self, user_id):
        key = db.get_decrypted_key(user_id)  # Dangerous!
        return key

# ✅ Secure Alternative
class SecureBot:
    """If users need to migrate funds, provide secure alternatives"""
    
    async def migrate_funds(self, user_id: str, destination: str):
        """
        When users want to withdraw funds, transfer directly to specified address
        instead of exporting private keys
        """
        # 1. Strict identity verification
        if not await self.verify_2fa(user_id):
            raise AuthError("2FA verification required")
        
        # 2. Validate destination address
        if not self.is_valid_address(destination):
            raise ValueError("Invalid destination address")
        
        # 3. Address confirmation (prevent address poisoning)
        confirmed = await self.confirm_address_with_user(
            user_id, 
            destination,
            show_first_last_chars=True
        )
        if not confirmed:
            raise UserCancelled()
        
        # 4. Transfer all assets
        balance = await self.get_balance(user_id)
        tx = await self.transfer(user_id, destination, balance)
        
        # 5. Destroy local wallet
        await self.destroy_wallet(user_id)
        
        return tx
    
    async def confirm_address_with_user(self, user_id, address, show_first_last_chars):
        """Have user confirm first and last characters of address to prevent address poisoning attacks"""
        message = f"""
⚠️ Please confirm receiving address:

Full address: {address}
First 6 chars: {address[:6]}
Last 6 chars: {address[-6:]}

Is this the address you want to transfer to?
        """
        return await self.get_user_confirmation(user_id, message)
```

---

## IV. Social Engineering and Phishing Prevention

### 4.1 Comment Section Phishing Attacks

| Item | Content |
|-----|------|
| **Check Item** | Whether the platform's comment section has effective phishing link protection |
| **Status** | ☐ Pending Review |

**Risk Description**

The comment section of prediction markets is an important place for user communication but has also become a channel for attackers to deploy phishing links. Attackers use obfuscated links and official identity impersonation to lure users to phishing websites.

**Severity**: 🟠 **High** — Large-scale credential and fund theft

**Real-World Case: Polymarket Comment Section Phishing Attack (November 2025)**

```
Incident Date: November 2025
Loss Amount: Over $500,000
Disclosed by: Senior Polymarket trader @25usdc

Attack Methods:
1. Attackers posted phishing links in Polymarket comment sections
2. Used obfuscated formats to hide real URLs
3. Bait message: "Why aren't you trading on the Polymarket private market? The odds are always better there!"

Attack Flow:
┌──────────────────────────────────────────────────────────┐
│  1. Attacker posts obfuscated link in market comments        │
│     └─ "Click to join Polymarket private market, better odds!" │
│                          ↓                                │
│  2. User clicks link, enters disguised Polymarket website   │
│     └─ Interface almost identical to official              │
│                          ↓                               │
│  3. User attempts to log in via email                      │
│     └─ Enters email and verification code                  │
│                          ↓                                │
│  4. Phishing site injects malicious script                 │
│     └─ Obtains user credentials and session                │
│                          ↓                                │
│  5. Attacker uses stolen credentials to log into real account │
│     └─ Transfers user funds                                │
└───────────────────────────────────────────────────────────┘

Attacker Characteristics:
- Continuously changed wallet addresses
- Encrypted all operations
- Shut down servers after each attack to eliminate traces
- Professional and organized operations

Most Affected Users: Users with Ethereum wallets

Aftermath (January 2026):
- Single user lost $90,000 from clicking phishing link
- Phishing attacks continued for months
- Users called for platform to implement comment moderation or upvote/downvote system
```

**Remediation Recommendations**

```python
# ✅ Multi-layer anti-phishing system
class AntiPhishingSystem:
    def __init__(self):
        self.known_phishing_domains = self.load_phishing_database()
        self.official_domains = ['polymarket.com', 'www.polymarket.com']
        self.link_shortener_domains = ['bit.ly', 't.co', 'tinyurl.com']
    
    def scan_comment(self, comment: str) -> ScanResult:
        """Scan comment for suspicious content"""
        issues = []
        
        # 1. Extract all URLs (including obfuscated ones)
        urls = self.extract_urls(comment, include_obfuscated=True)
        
        for url in urls:
            # 2. Check known phishing domains
            if self.is_known_phishing(url):
                issues.append(Issue(severity='CRITICAL', type='KNOWN_PHISHING', url=url))
                continue
            
            # 3. Check link shortening services (may hide real destination)
            if self.uses_url_shortener(url):
                expanded = self.expand_url(url)
                if expanded and self.is_suspicious(expanded):
                    issues.append(Issue(severity='HIGH', type='SUSPICIOUS_SHORTENED', url=url))
            
            # 4. Check lookalike official domains (e.g., polymarket.co, poly-market.com)
            if self.is_lookalike_domain(url):
                issues.append(Issue(severity='HIGH', type='LOOKALIKE_DOMAIN', url=url))
            
            # 5. Check Unicode homograph attacks (e.g., replacing 'po' with 'рο')
            if self.contains_homograph(url):
                issues.append(Issue(severity='HIGH', type='HOMOGRAPH_ATTACK', url=url))
        
        # 6. Check social engineering keywords
        if self.contains_phishing_keywords(comment):
            issues.append(Issue(severity='MEDIUM', type='SUSPICIOUS_KEYWORDS'))
        
        return ScanResult(issues=issues, should_block=any(i.severity == 'CRITICAL' for i in issues))
    
    def is_lookalike_domain(self, url: str) -> bool:
        """Detect lookalike domains"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check similarity to official domains
        for official in self.official_domains:
            similarity = self.calculate_similarity(domain, official)
            if 0.7 < similarity < 1.0:  # Similar but not exact
                return True
            
            # Check common variants
            if any(variant in domain for variant in [
                'polymarket-', 'poly-market', 'polymarkets', 
                'polymarket.co', 'polymarket.io', 'polymarket.xyz'
            ]):
                return True
        
        return False
    
    def contains_phishing_keywords(self, text: str) -> bool:
        """Detect phishing language"""
        keywords = [
            'private market', 'better odds',
            'exclusive access', 'verify your account',
            'claim your rewards', 'urgent action required'
        ]
        text_lower = text.lower()
        return any(kw.lower() in text_lower for kw in keywords)

# ✅ Frontend security enhancement
class FrontendSecurity:
    def render_comment(self, comment: str) -> str:
        """Safely render comments"""
        # 1. HTML escape
        escaped = html.escape(comment)
        
        # 2. Link processing
        links = re.findall(r'https?://\S+', escaped)
        for link in links:
            # Add security warning
            safe_link = f'''
                <span class="external-link-warning">
                    <a href="{link}" 
                       onclick="return confirmExternalLink('{link}')"
                       rel="noopener noreferrer nofollow"
                       target="_blank">
                        {self.truncate_url(link)}
                    </a>
                    ⚠️ External Link
                </span>
            '''
            escaped = escaped.replace(link, safe_link)
        
        return escaped
```

```javascript
// ✅ Frontend external link confirmation
function confirmExternalLink(url) {
    const officialDomains = ['polymarket.com', 'www.polymarket.com'];
    const urlObj = new URL(url);
    
    if (officialDomains.includes(urlObj.hostname)) {
        return true;  // Official links pass through directly
    }
    
    // Show warning dialog
    const confirmed = confirm(`
⚠️ You are about to leave Polymarket

Destination: ${urlObj.hostname}

Please note:
• This is NOT an official Polymarket website
• Do not enter your login credentials on any other website
• Polymarket does not have a "private market"

Are you sure you want to continue?
    `);
    
    return confirmed;
}
```

---

### 4.2 Malicious Third-Party Tools

| Item | Content |
|-----|------|
| **Check Item** | Whether there is a warning mechanism for malicious third-party tools |
| **Status** | ☐ Pending Review |

**Risk Description**

With the development of the prediction market ecosystem, various third-party tools have emerged (such as trading bots, data analysis tools). Some malicious tools may contain backdoor code that steals user private keys or credentials.

**Severity**: 🔴 **Critical** — User private keys stolen

**Real-World Case: GitHub Malicious Polymarket Copy Trading Bot (December 2025)**

```
Incident Date: December 2025
Disclosed by: SlowMist Chief Information Security Officer 23pds

Discovery Process:
1. Community users discovered a Polymarket copy trading bot on GitHub
2. Code contained malicious code
3. SlowMist 23pds forwarded the warning

Malicious Code Behavior:
- Steals user-entered private keys/seed phrases
- Sends sensitive information to attacker servers
- Disguised as normal functional code, not easily detected

Risk Warning:
- Open source does not equal secure
- Copy trading bots require high privileges
- Users may let their guard down seeking convenience
```

**Remediation Recommendations**

```python
# ✅ Official tool verification system
class OfficialToolRegistry:
    """Registry of officially certified third-party tools"""
    
    def __init__(self):
        self.verified_tools = {}
        self.reported_malicious = set()
    
    async def verify_tool(self, tool_url: str) -> VerificationResult:
        """Verify third-party tool"""
        # 1. Check if in malicious list
        if tool_url in self.reported_malicious:
            return VerificationResult(
                status='MALICIOUS',
                message='This tool has been reported as malware'
            )
        
        # 2. Check if officially certified
        if tool_url in self.verified_tools:
            return VerificationResult(
                status='VERIFIED',
                message='This tool has passed official security review',
                audit_report=self.verified_tools[tool_url].audit_report
            )
        
        # 3. Unknown tool warning
        return VerificationResult(
            status='UNKNOWN',
            message='This tool has not been officially verified, use at your own risk'
        )
    
    def get_safety_tips(self) -> str:
        return """
⚠️ Third-Party Tool Safety Tips:

1. Never enter private keys/seed phrases into any third-party tools
2. Prioritize using officially certified tools
3. Open source code may also contain malicious code, please review carefully
4. Use a separate test wallet to verify first
5. Follow official security announcements and community warnings
6. If you find suspicious tools, please report immediately

Official Certified Tools List: https://polymarket.com/verified-tools
        """
```


- **User Self-Check List (Before Using Third-Party Tools):**

| Check Item                            | Confirmed |   Risk Level |
|----------------------------------|-------|-----------|
| Is the tool officially recommended/certified |   ☐   |  If no: 🔴  |
| Does it require entering private keys/seed phrases |   ☐   |  If yes: 🔴  |
| Is the code open source and auditable |   ☐   |  If no: 🟠  |
| Is there an independent security audit report |   ☐   |  If no: 🟠  |
| Community reviews and usage history |   ☐   |  If poor: 🟠  |
| Is the developer/team traceable |   ☐   |  If no: 🟠  |
| Test with a test wallet first |   ☐   |  Recommended ✅    |



---

## V. Smart Contract Security

### 5.1 Market Settlement Logic Security

| Item | Content |
|-----|------|
| **Check Item** | Whether market settlement logic has vulnerabilities |
| **Status** | ☐ Pending Review |

**Risk Description**

The core of prediction markets is fund settlement based on event outcomes. Vulnerabilities in settlement logic may lead to incorrect fund distribution, malicious exploitation, or locked funds.

**Severity**: 🔴 **Critical** — Incorrect fund distribution or theft

**Prediction Market-Specific Attack Scenario Analysis**

```
Scenario 1: Settlement Timing Manipulation
┌───────────────────────────────────┐
│ Attack Flow:                        │
│ 1. Market is about to expire, outcome still unclear │
│ 2. Attacker buys large positions in one direction   │
│ 3. Submits false settlement before outcome announcement │
│ 4. Profits from time difference                │
│                                   │
│ Prevention: Introduce settlement delay + multi-party verification │
└───────────────────────────────────┘

Scenario 2: Invalid Market Abuse
┌───────────────────────────────────────────┐
│ Attack Flow:                                  │
│ 1. Attacker creates market with ambiguous rules    │
│ 2. Attracts large user participation              │
│ 3. Claims market is "invalid" at settlement       │
│ 4. Triggers proportional refunds while profiting from trading fees │
│                                            │
│ Prevention: Strict market creation review + creator penalties for invalid markets │
└────────────────────────────────────────────┘

Scenario 3: Settlement Value Manipulation
┌───────────────────────────────────────────┐
│ For numeric markets (e.g., "BTC year-end price"):  │
│ 1. Attacker holds positions in specific price range  │
│ 2. Manipulates spot market price at settlement time  │
│ 3. Profits from brief price deviation              │
│                                           │
│ Prevention: Use TWAP + multiple data sources + outlier removal │
└───────────────────────────────────────────┘
```

**Remediation Recommendations**

```solidity
// ✅ Secure market settlement contract
contract SecurePredictionMarket {
    uint256 public constant SETTLEMENT_DELAY = 24 hours;
    uint256 public constant DISPUTE_WINDOW = 48 hours;
    uint256 public constant MIN_SETTLEMENT_SOURCES = 3;
    
    enum MarketState { Active, PendingSettlement, Disputed, Settled, Invalid }
    
    struct Market {
        bytes32 id;
        MarketState state;
        uint8 proposedOutcome;
        uint256 proposedAt;
        address proposer;
        uint256 yesPool;
        uint256 noPool;
        mapping(address => uint256) yesPositions;
        mapping(address => uint256) noPositions;
    }
    
    // 1. Propose settlement (requires stake)
    function proposeSettlement(
        bytes32 marketId, 
        uint8 outcome,
        bytes[] calldata proofs  // Proofs from multiple data sources
    ) external payable {
        Market storage market = markets[marketId];
        require(market.state == MarketState.Active, "Market not active");
        require(block.timestamp >= market.endTime, "Market not ended");
        require(proofs.length >= MIN_SETTLEMENT_SOURCES, "Insufficient proofs");
        require(msg.value >= SETTLEMENT_BOND, "Insufficient bond");
        
        // Verify multiple data sources are consistent
        for (uint i = 0; i < proofs.length; i++) {
            require(
                verifyProof(proofs[i], outcome),
                "Proof does not support outcome"
            );
        }
        
        market.proposedOutcome = outcome;
        market.proposedAt = block.timestamp;
        market.proposer = msg.sender;
        market.state = MarketState.PendingSettlement;
        
        emit SettlementProposed(marketId, outcome, msg.sender);
    }
    
    // 2. Dispute mechanism
    function disputeSettlement(
        bytes32 marketId,
        uint8 alternativeOutcome,
        string calldata evidence
    ) external payable {
        Market storage market = markets[marketId];
        require(market.state == MarketState.PendingSettlement, "Not pending");
        require(
            block.timestamp < market.proposedAt + DISPUTE_WINDOW,
            "Dispute window closed"
        );
        require(msg.value >= DISPUTE_BOND, "Insufficient bond");
        
        market.state = MarketState.Disputed;
        
        emit SettlementDisputed(marketId, alternativeOutcome, evidence, msg.sender);
        // Trigger oracle voting or arbitration process
    }
    
    // 3. Finalize settlement
    function finalizeSettlement(bytes32 marketId) external {
        Market storage market = markets[marketId];
        require(market.state == MarketState.PendingSettlement, "Not pending");
        require(
            block.timestamp >= market.proposedAt + DISPUTE_WINDOW,
            "Dispute window active"
        );
        
        market.state = MarketState.Settled;
        
        // Return proposer's stake
        payable(market.proposer).transfer(SETTLEMENT_BOND);
        
        emit MarketSettled(marketId, market.proposedOutcome);
    }
    
    // 4. Secure fund withdrawal
    function claimWinnings(bytes32 marketId) external nonReentrant {
        Market storage market = markets[marketId];
        require(market.state == MarketState.Settled, "Market not settled");
        
        uint256 payout;
        if (market.proposedOutcome == 1) {  // Yes wins
            uint256 position = market.yesPositions[msg.sender];
            require(position > 0, "No winning position");
            
            // Calculate payout: proportionally distribute losing pool
            uint256 totalWinningPool = market.yesPool;
            uint256 totalLosingPool = market.noPool;
            payout = position + (position * totalLosingPool / totalWinningPool);
            
            market.yesPositions[msg.sender] = 0;
        } else {
            // No wins - similar logic
        }
        
        // Safe transfer
        (bool success, ) = msg.sender.call{value: payout}("");
        require(success, "Transfer failed");
        
        emit WinningsClaimed(marketId, msg.sender, payout);
    }
}
```

---

## VI. Cross-Chain Bridge Security

### 6.1 Cross-Chain Fund Bridging Risk

| Item | Content |
|-----|------|
| **Check Item** | Whether cross-chain bridge functionality has sufficient security verification |
| **Status** | ☐ Pending Review |

**Risk Description**

Prediction markets (such as Polymarket) often integrate cross-chain bridges (such as deBridge) to allow users to deposit funds from other chains. Cross-chain bridging involves complex message verification and is a high-risk attack target.

**Severity**: 🔴 **Critical** — Cross-chain funds stolen or forged

**Polycule Cross-Chain Bridge Risk Analysis**

```
Polycule's deBridge Integration Risk Points:

1. Auto-Swap Risk
   - Default extracts 2% SOL to swap for POL as Gas
   - If exchange rate interface is manipulated, may cause excessive losses
   - Improper slippage settings may be vulnerable to MEV attacks

2. Cross-Chain Message Verification Risk
   - If deBridge receipt verification is not strict
   - May lead to false deposits
   - Or duplicate credits

3. Execution Permission Risk
   - Cross-chain callbacks may be exploited
   - Insufficient parameter validation may lead to fund transfers

Prediction Market-Specific Cross-Chain Risks:
- Users may deposit from multiple chains
- Funds aggregated to single hot wallet
- Hot wallet becomes high-value target
```

**Remediation Recommendations**

```solidity
// ✅ Secure cross-chain fund receiver
contract SecureBridgeReceiver {
    address public immutable DEBRIDGE_GATE;
    mapping(bytes32 => bool) public processedTransfers;
    
    uint256 public dailyLimit;
    uint256 public dailyReceived;
    uint256 public lastResetDay;
    
    // Auto-swap parameters
    uint256 public constant MAX_SWAP_SLIPPAGE = 100;  // 1%
    uint256 public constant MAX_AUTO_SWAP_PERCENTAGE = 300;  // 3%
    
    modifier onlyBridge() {
        require(msg.sender == DEBRIDGE_GATE, "Only bridge");
        _;
    }
    
    function receiveCrossChainFunds(
        bytes32 transferId,
        address recipient,
        uint256 amount,
        uint256 sourceChain,
        bytes calldata proof
    ) external onlyBridge nonReentrant {
        // 1. Replay prevention
        require(!processedTransfers[transferId], "Already processed");
        processedTransfers[transferId] = true;
        
        // 2. Verify proof
        require(
            verifyBridgeProof(transferId, recipient, amount, sourceChain, proof),
            "Invalid proof"
        );
        
        // 3. Daily limit check
        _checkDailyLimit(amount);
        
        // 4. Large transfer delay
        if (amount > LARGE_TRANSFER_THRESHOLD) {
            pendingLargeTransfers[transferId] = LargeTransfer({
                recipient: recipient,
                amount: amount,
                unlockTime: block.timestamp + LARGE_TRANSFER_DELAY
            });
            emit LargeTransferPending(transferId, recipient, amount);
            return;
        }
        
        // 5. Execute transfer
        _creditUser(recipient, amount);
        
        emit CrossChainFundsReceived(transferId, recipient, amount, sourceChain);
    }
    
    function executeAutoSwap(
        uint256 inputAmount,
        uint256 minOutputAmount,
        address[] calldata path
    ) internal returns (uint256) {
        // 1. Check swap ratio does not exceed limit
        require(
            inputAmount <= totalDeposit * MAX_AUTO_SWAP_PERCENTAGE / 10000,
            "Swap amount too high"
        );
        
        // 2. Calculate expected output
        uint256 expectedOutput = getExpectedOutput(inputAmount, path);
        
        // 3. Slippage protection
        require(
            minOutputAmount >= expectedOutput * (10000 - MAX_SWAP_SLIPPAGE) / 10000,
            "Slippage too high"
        );
        
        // 4. Execute swap
        return dex.swap(inputAmount, minOutputAmount, path);
    }
}
```

---

## VII. Copy Trading Security

### 7.1 Copy Trading Event Verification

| Item | Content |
|-----|------|
| **Check Item** | Whether copy trading has event source verification |
| **Status** | ☐ Pending Review |

**Risk Description**

Copy trading functionality allows users to automatically follow target wallet trades. If monitored on-chain events can be forged, or if there is no security filtering of target trades, follower funds may be directed to malicious contracts.

**Severity**: 🔴 **Critical** — Follower user funds stolen

**Polycule Copy Trading Risk Analysis**

```
Polycule /copytrade Feature Risks:

1. Event Listening Risk
   - Bot continuously monitors target wallet's on-chain activity
   - If event source verification is not strict, may be deceived by forged events
   
2. Auto-Execution Risk
   - Follower users' trades are auto-signed and executed by backend
   - No user confirmation required
   - If target wallet interacts with malicious contract, followers are also affected

3. Target Wallet Poisoning
   - Attacker sends malicious tokens to target wallet
   - When target wallet interacts with token, triggers malicious logic
   - Followers copy the interaction, funds stolen

4. Advanced Feature Risks
   - Reverse copy trading, custom rules, etc.
   - Increases logic complexity and potential vulnerabilities
```

**Remediation Recommendations**

```python
# ✅ Secure copy trading implementation
class SecureCopyTrading:
    def __init__(self):
        # Whitelist
        self.verified_markets = self.load_polymarket_markets()
        self.token_whitelist = self.load_verified_tokens()
        
        # Blacklist
        self.known_scam_contracts = self.load_scam_database()
        self.suspicious_wallets = set()
    
    async def process_copy_event(self, event: TradeEvent) -> Optional[Trade]:
        """Process copy event with multi-layer security filtering"""
        
        # 1. Verify event's authentic origin
        if not await self.verify_event_origin(event):
            await self.log_security_event("SPOOFED_EVENT", event)
            return None
        
        # 2. Verify it's an official Polymarket market
        if event.market_id not in self.verified_markets:
            await self.log_security_event("UNKNOWN_MARKET", event)
            return None
        
        # 3. Check if interacting contract is whitelisted
        if not self.is_whitelisted_contract(event.contract_address):
            await self.log_security_event("NON_WHITELISTED_CONTRACT", event)
            return None
        
        # 4. Check if involves known malicious addresses
        if event.contract_address in self.known_scam_contracts:
            await self.log_security_event("SCAM_CONTRACT", event)
            await self.alert_user("Target wallet interacted with known malicious contract, copy blocked")
            return None
        
        # 5. Anomalous behavior detection
        if await self.detect_anomalous_pattern(event):
            await self.log_security_event("ANOMALOUS_PATTERN", event)
            # Don't auto-block, but notify user
            await self.alert_user(f"Anomalous trading pattern detected, please confirm if you want to continue copying")
            return None
        
        # 6. Amount limits
        copy_amount = self.calculate_copy_amount(event)
        if copy_amount > self.user_settings.max_single_trade:
            copy_amount = self.user_settings.max_single_trade
            await self.alert_user(f"Trade amount adjusted to limit {copy_amount}")
        
        # 7. Build secure copy trade
        return Trade(
            market_id=event.market_id,
            direction=event.direction,
            amount=copy_amount,
            max_slippage=self.user_settings.max_slippage,
            deadline=block.timestamp + 300  # 5 minute validity
        )
    
    async def verify_event_origin(self, event: TradeEvent) -> bool:
        """Strictly verify event origin"""
        # Get original transaction
        tx = await self.web3.eth.get_transaction(event.tx_hash)
        tx_receipt = await self.web3.eth.get_transaction_receipt(event.tx_hash)
        
        # 1. Verify transaction initiator is target wallet
        if tx['from'].lower() != self.target_wallet.lower():
            return False
        
        # 2. Verify transaction succeeded
        if tx_receipt['status'] != 1:
            return False
        
        # 3. Verify block confirmations (prevent reorg attacks)
        current_block = await self.web3.eth.block_number
        confirmations = current_block - tx_receipt['blockNumber']
        if confirmations < self.required_confirmations:
            return False
        
        # 4. Verify event was actually emitted in the transaction
        event_found = False
        for log in tx_receipt['logs']:
            if self.matches_event(log, event):
                event_found = True
                break
        
        return event_found
    
    async def detect_anomalous_pattern(self, event: TradeEvent) -> bool:
        """Detect anomalous trading patterns"""
        target_history = await self.get_recent_trades(self.target_wallet, hours=24)
        
        # 1. Sudden large trades
        avg_size = sum(t.amount for t in target_history) / len(target_history) if target_history else 0
        if event.amount > avg_size * 5:
            return True
        
        # 2. High-frequency trading (may be wash trading)
        recent_trades = [t for t in target_history if t.timestamp > time.time() - 3600]
        if len(recent_trades) > 20:  # Over 20 trades in 1 hour
            return True
        
        # 3. Repeated buying/selling same market (may be volume farming)
        market_trades = [t for t in recent_trades if t.market_id == event.market_id]
        if len(market_trades) > 5:
            buy_count = sum(1 for t in market_trades if t.direction == 'buy')
            sell_count = len(market_trades) - buy_count
            if buy_count > 0 and sell_count > 0:
                return True
        
        return False
```

---

## VIII. Client-Side Security

### 8.1 Wallet Connection Security

| Item | Content |
|-----|------|
| **Check Item** | Whether wallet connection flow has sufficient security protection |
| **Status** | ☐ Pending Review |

**Risk Description**

When users connect wallets, if they sign malicious authorization transactions, funds may be stolen. Prediction markets require users to sign various transactions (betting, withdrawing, etc.), and each signing request is a potential attack point.

**Severity**: 🟠 **High** — User wallet authorization abused

**Prediction Market-Specific Signing Risks**

```
Types of transactions prediction market users need to sign:

1. Token Approval (approve)
   - Risk: Unlimited approval may be abused
   - Recommendation: Only approve required amount each time

2. Betting Transactions
   - Risk: Parameters may be tampered (amount, market, direction)
   - Recommendation: Display complete transaction details before signing

3. Conditional Token Operations
   - Risk: Complex token logic difficult to understand
   - Recommendation: User-friendly transaction explanations

4. Batch Operations
   - Risk: Multiple operations bundled may hide malicious transactions
   - Recommendation: Display each operation separately

Phishing Attack Patterns:
- Phishing sites disguised as Polymarket
- Trick users into signing unlimited approvals
- Use authorization to transfer all user tokens
```

**Remediation Recommendations**

```javascript
// ✅ Secure wallet interaction implementation
class SecureWalletInteraction {
    constructor() {
        this.MAX_APPROVAL_AMOUNT = ethers.utils.parseUnits('10000', 6);  // Max approval 10000 USDC
    }
    
    async placeBet(marketId, direction, amount) {
        // 1. Check current approval amount
        const currentAllowance = await this.usdc.allowance(
            this.userAddress, 
            this.marketContract.address
        );
        
        // 2. If approval insufficient, request exact approval (not unlimited)
        if (currentAllowance.lt(amount)) {
            const approvalNeeded = amount.sub(currentAllowance);
            
            // Display approval request details
            const confirmed = await this.showApprovalDialog({
                token: 'USDC',
                amount: ethers.utils.formatUnits(approvalNeeded, 6),
                spender: this.marketContract.address,
                spenderName: 'Polymarket Betting Contract',
                warning: 'Only approve required amount, unlimited approval not recommended'
            });
            
            if (!confirmed) return { status: 'cancelled' };
            
            // Execute exact approval
            await this.usdc.approve(this.marketContract.address, amount);
        }
        
        // 3. Build betting transaction
        const tx = await this.marketContract.populateTransaction.placeBet(
            marketId,
            direction,
            amount
        );
        
        // 4. Display transaction preview
        const preview = await this.buildTransactionPreview(tx, {
            action: 'Bet',
            market: await this.getMarketName(marketId),
            direction: direction ? 'YES' : 'NO',
            amount: ethers.utils.formatUnits(amount, 6) + ' USDC',
            estimatedPayout: await this.calculateEstimatedPayout(marketId, direction, amount),
            gasEstimate: await this.estimateGas(tx)
        });
        
        const userConfirmed = await this.showTransactionPreview(preview);
        if (!userConfirmed) return { status: 'cancelled' };
        
        // 5. Execute transaction
        return await this.signer.sendTransaction(tx);
    }
    
    async showApprovalDialog(details) {
        return new Promise((resolve) => {
            const dialog = document.createElement('div');
            dialog.innerHTML = `
                <div class="approval-dialog">
                    <h3>🔐 Token Approval Request</h3>
                    <div class="details">
                        <p><strong>Token:</strong> ${details.token}</p>
                        <p><strong>Approval Amount:</strong> ${details.amount}</p>
                        <p><strong>Approve To:</strong> ${details.spenderName}</p>
                        <p><strong>Contract Address:</strong> 
                            <code>${details.spender.slice(0, 10)}...${details.spender.slice(-8)}</code>
                        </p>
                    </div>
                    <div class="warning">⚠️ ${details.warning}</div>
                    <div class="buttons">
                        <button class="cancel">Cancel</button>
                        <button class="confirm">Confirm Approval</button>
                    </div>
                </div>
            `;
            
            dialog.querySelector('.cancel').onclick = () => {
                dialog.remove();
                resolve(false);
            };
            
            dialog.querySelector('.confirm').onclick = () => {
                dialog.remove();
                resolve(true);
            };
            
            document.body.appendChild(dialog);
        });
    }
}
```

---

## IX. Operations and Incident Response

### 9.1 Security Monitoring System

| Item | Content |
|-----|------|
| **Check Item** | Whether there is monitoring for prediction market-specific risks |
| **Status** | ☐ Pending Review |

**Risk Description**

Prediction markets have unique risk patterns (such as oracle manipulation, market outcome disputes, large copy trades, etc.) that require dedicated monitoring systems for timely detection and response.

**Severity**: 🟠 **High** — Security incident detection delayed, losses amplified

**Prediction Market-Specific Monitoring Metrics**

```python
# ✅ Prediction market security monitoring system
class PredictionMarketMonitor:
    def __init__(self):
        self.alert_channels = [SlackAlert(), PagerDuty(), TelegramAlert()]
    
    async def monitor_oracle_voting(self):
        """Monitor oracle voting anomalies"""
        while True:
            active_votes = await self.get_active_oracle_votes()
            
            for vote in active_votes:
                # 1. Detect voting power concentration
                top_voters = await self.get_top_voters(vote.id)
                if top_voters[0].percentage > 20:
                    await self.alert(
                        level='HIGH',
                        event='CONCENTRATED_VOTING_POWER',
                        details={
                            'vote_id': vote.id,
                            'market': vote.market_id,
                            'top_voter_percentage': top_voters[0].percentage
                        }
                    )
                
                # 2. Detect sudden vote swings
                vote_history = await self.get_vote_history(vote.id, hours=1)
                if self.detect_sudden_swing(vote_history):
                    await self.alert(
                        level='HIGH',
                        event='SUDDEN_VOTE_SWING',
                        details={
                            'vote_id': vote.id,
                            'swing_percentage': self.calculate_swing(vote_history)
                        }
                    )
            
            await asyncio.sleep(300)  # Check every 5 minutes
    
    async def monitor_large_positions(self):
        """Monitor large position changes"""
        while True:
            recent_trades = await self.get_recent_trades(minutes=10)
            
            for trade in recent_trades:
                # 1. Large trade alert
                if trade.value > LARGE_TRADE_THRESHOLD:
                    await self.alert(
                        level='MEDIUM',
                        event='LARGE_TRADE',
                        details={
                            'market': trade.market_id,
                            'value': trade.value,
                            'direction': trade.direction,
                            'trader': trade.trader[:10] + '...'
                        }
                    )
                
                # 2. Large trades near expiry (may be insider trading)
                market = await self.get_market(trade.market_id)
                time_to_expiry = market.end_time - time.time()
                if time_to_expiry < 3600 and trade.value > LARGE_TRADE_THRESHOLD / 2:
                    await self.alert(
                        level='HIGH',
                        event='LARGE_LATE_TRADE',
                        details={
                            'market': trade.market_id,
                            'value': trade.value,
                            'minutes_to_expiry': time_to_expiry / 60
                        }
                    )
            
            await asyncio.sleep(60)
    
    async def monitor_bot_activity(self):
        """Monitor trading bot service status"""
        while True:
            # 1. Check bot service health
            bot_services = await self.get_bot_services()
            for service in bot_services:
                health = await self.check_health(service)
                if not health.is_healthy:
                    await self.alert(
                        level='CRITICAL',
                        event='BOT_SERVICE_DOWN',
                        details={'service': service.name, 'last_seen': health.last_seen}
                    )
            
            # 2. Check abnormal signing activity
            signing_stats = await self.get_signing_statistics(minutes=10)
            if signing_stats.rate > NORMAL_SIGNING_RATE * 3:
                await self.alert(
                    level='HIGH',
                    event='ABNORMAL_SIGNING_RATE',
                    details={
                        'current_rate': signing_stats.rate,
                        'normal_rate': NORMAL_SIGNING_RATE
                    }
                )
            
            await asyncio.sleep(60)
    
    async def monitor_phishing_reports(self):
        """Monitor phishing reports"""
        while True:
            # 1. Scan social media keywords
            mentions = await self.scan_social_media([
                'polymarket scam', 'polymarket phishing',
                'polymarket hack', 'polymarket stolen'
            ])
            
            if len(mentions) > MENTION_THRESHOLD:
                await self.alert(
                    level='HIGH',
                    event='ELEVATED_SCAM_REPORTS',
                    details={
                        'mention_count': len(mentions),
                        'sample': mentions[:5]
                    }
                )
            
            # 2. Check newly reported phishing domains
            new_phishing_domains = await self.get_new_phishing_reports()
            for domain in new_phishing_domains:
                await self.add_to_blocklist(domain)
                await self.alert(
                    level='MEDIUM',
                    event='NEW_PHISHING_DOMAIN',
                    details={'domain': domain}
                )
            
            await asyncio.sleep(900)  # Check every 15 minutes
```

---

### 9.2 Incident Response Plan

| Item | Content |
|-----|------|
| **Check Item** | Whether there is an incident response plan for prediction market scenarios |
| **Status** | ☐ Pending Review |

**Prediction Market Incident Response Handbook**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    Prediction Market Incident Response Handbook
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario 1: Trading Bot Compromised
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reference Case: Polycule Attack (January 2026)

Immediate Response (0-15 minutes):
☐ Immediately shut down bot service
☐ Revoke all API keys
☐ Freeze hot wallet (if authorized)
☐ Post preliminary announcement on official channels

Short-term Response (15 minutes - 2 hours):
☐ Assess scope of fund losses
☐ Track stolen fund flows
☐ Contact exchanges to freeze suspicious addresses
☐ Collect evidence (logs, transaction records)
☐ Notify affected users

Follow-up Actions:
☐ Complete security audit
☐ Publish detailed post-mortem report
☐ Develop compensation plan
☐ Implement security hardening measures

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario 2: Oracle Manipulation Attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reference Case: Polymarket UMA Manipulation Attack (March 2025)

Immediate Response:
☐ Pause settlement of affected market
☐ Contact oracle provider
☐ Collect voting data and evidence
☐ Assess possibility of retroactive correction

Short-term Response:
☐ Coordinate solution with oracle team
☐ Explain situation to users
☐ Assess whether re-voting is needed
☐ Consider declaring market invalid

Long-term Improvements:
☐ Review oracle selection criteria
☐ Implement voting power concentration limits
☐ Add dispute resolution mechanisms
☐ Consider multi-oracle solutions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario 3: Large-Scale Phishing Attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reference Case: Polymarket Comment Section Phishing (November 2025)

Immediate Response:
☐ Post warnings on all official channels
☐ Temporarily disable comment functionality (if applicable)
☐ Collect and block phishing links
☐ Contact domain registrars to report phishing domains

Short-term Response:
☐ Implement comment filtering system
☐ Add external link warnings
☐ Contact search engines to flag phishing sites
☐ Provide support for victims

Long-term Improvements:
☐ Deploy automated phishing detection
☐ Establish community reporting mechanism
☐ Strengthen user security education
☐ Consider comment moderation system

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario 4: Third-Party Authentication Vulnerability
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reference Case: Polymarket Magic Labs Vulnerability (December 2024)

Immediate Response:
☐ Disable affected authentication method
☐ Force all users to re-login
☐ Contact third-party provider
☐ Issue user notification

Short-term Response:
☐ Assess scope of affected accounts
☐ Provide alternative login methods for affected users
☐ Monitor abnormal login activity
☐ Consider temporarily enhanced authentication requirements

Long-term Improvements:
☐ Review security of all third-party integrations
☐ Implement multi-factor authentication
☐ Establish third-party provider security assessment process
☐ Consider backup authentication solutions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Complete Checklist Summary

| Category | Check Item | Priority | Reference Case | Status |
|-----|-------|-------|---------|------|
| **Third-Party Auth** | Authentication provider vulnerability assessment | P0 | Polymarket Magic Labs Vulnerability | ☐ |
| | OAuth/Social login security | P0 | Polymarket Google Account Attack | ☐ |
| | OTP length and attempt limits | P0 | 3-digit OTP brute force | ☐ |
| **Oracle Security** | Voting power concentration check | P0 | UMA $7M manipulation | ☐ |
| | Market rule clarity | P1 | Trump conviction market dispute | ☐ |
| | Dispute resolution mechanism | P1 | UMA voting dispute | ☐ |
| **Trading Bots** | Private key storage security | P0 | Polycule $230K theft | ☐ |
| | Private key export interface security | P0 | Polycule /wallet feature | ☐ |
| | Transaction confirmation mechanism | P1 | Bot auto-signing risk | ☐ |
| **Phishing Prevention** | Comment section link filtering | P0 | $500K phishing attack | ☐ |
| | External link warnings | P1 | $90K single user loss | ☐ |
| | Malicious third-party tool alerts | P1 | GitHub malicious bot | ☐ |
| **Smart Contracts** | Market settlement logic | P0 | Settlement timing manipulation risk | ☐ |
| | Fund withdrawal security | P0 | Reentrancy attack protection | ☐ |
| **Cross-Chain Bridge** | Bridge message verification | P0 | deBridge integration risk | ☐ |
| | Auto-swap parameters | P1 | Slippage/rate manipulation | ☐ |
| **Copy Trading** | Event source verification | P0 | Polycule /copytrade | ☐ |
| | Target trade filtering | P1 | Malicious contract copy risk | ☐ |
| **Client-Side** | Wallet authorization control | P1 | Unlimited approval risk | ☐ |
| | Transaction preview confirmation | P1 | Parameter tampering protection | ☐ |
| **Operations** | Oracle voting monitoring | P0 | UMA voting anomaly | ☐ |
| | Phishing report monitoring | P1 | Social media sentiment | ☐ |
| | Incident response plan | P0 | Multi-scenario response handbook | ☐ |

---

## Conclusion

Prediction markets are an emerging sector that integrates complex domains including finance, game theory, and oracles. The multiple security incidents that occurred in 2024-2025 demonstrate that this field faces unique security challenges:

1. **Third-Party Dependency Risk**: Vulnerabilities in external components such as authentication services, oracles, and cross-chain bridges directly impact platform security
2. **Governance Attack Risk**: Oracle token concentration may lead to market resolution manipulation
3. **Convenience vs. Security Trade-off**: Convenient tools like Telegram bots enhance user experience while introducing custody risks
4. **Social Engineering Attacks**: Comment section phishing attacks exploit user trust for fraud

This checklist, summarized from real security incidents, aims to provide reference for prediction market project security development. Security is not a one-time effort but requires continuous iteration and improvement.

---

**Referenced Incidents**:
- Polycule Bot Attack (January 2026) - $230,000 loss
- Polymarket UMA Oracle Manipulation (March 2025) - $7 million market dispute
- Polymarket Comment Section Phishing (November 2025) - $500,000 loss
- Polymarket Magic Labs Authentication Vulnerability (December 2024)
- Polymarket Google Account Proxy Attack (September 2024)

**Disclaimer**: This document is for technical research and security audit reference only, and does not constitute any investment or legal advice.

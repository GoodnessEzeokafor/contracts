# Mogul Studios Continuous Organization

## Summary
The Continuous Organization smart contract system of Mogul Productions consists of several contracts. Main one of them is MogulOrganisation.sol defining the logic of the continuous organisation. In addition to Mogul Organisation, there are couple more contracts that deal with the complex mathematics of the CO formulas. In order to ensure the accuracy (and the feasibility of implementation of the formula) the actual formulas are written in vyper.


## Continuous organization lifecycle

The continuous organization has several states that it can be at. They are chronological and form the CO lifecycle. Bellow you will find the lifecycle states and transitions.

### Deployment
The first state in the lifecycle of the Mogul CO is its deployment. During deployment time several key configurations are passed. These are:
- address _bondingMath - the address of the solidity contract performing the CO formulas calculation (it calls the vyper contracts internally)
- address _mogulUSD - the address of the USD stable token used for contribution
- address _mogulToken - the address of the Mogul CO token. This token needs to be deployed beforehand and once the Mogul CO contract is deployed, the CO address should be made the "minter" of the Mogul Token.
- address _mogulBank - the address receiving the investment fund
- address _whiteLister - the address that has the privilege to whitelist investors. No address can invest if it is not whitelisted.

Once the deployment is complete the CO goes into the `LOCKED` state.


*Tech Note :* The token contract and bonding math contracts are deployed and accessed separately from the CO contract due to contract size limitations (we were hitting the gas limits).

### Locked
Once the CO is deployed it enters the Locked state. No contribution can happen in this state. The only function that can be called during this phase is `unlockOrganisation`.

#### unlockOrganisation
`unlockOrganisation(uint256 organiserUSDContribution, uint256 organiserMGLReward)` is the function used to unlock the CO for investment. It can only be called once and has two parameters - how much initial funds the admin is contributing to the organization (`organiserUSDContribution`) and how much MGL he is going to receive back for this contribution (`organiserMGLReward`).
These two parameters are crucial as their ratio defines the buy slope used in the calculations for the next investments.

Once the unlockOrganisation function is successfully executed the CO goes into the `LIVE` state.

### Live
This is the state that the CO will be during the majority of its life. During this stage investments, sells and dividends payouts can be done. You will find an overview of the available functions below

#### Invest
`function invest(uint256 usdAmount, bytes memory signedData) public onlyWhenLive` is the function used for investing in the CO. It can only be called when the CO is LIVE and has two parameters:
- usdAmount - the amount of USD you want to invest
- signedData - signature by the whitelister. This signature only needs to be passed if the investor is not whitelisted. Through this signature we have combined the whitelisting and investment process. The message signed by the whitelister should be keccak256 of the investor address.

This function has a set gasPrice to be called with in order to avoid front-running.

Once the function is called and the different sanity checks are performed the invest function checks whether the investor is whitelisted and performs the whitelisting ritual or reverts. After that, the function asks the BondingMathematics contract to calculate how much MGL should be minted and mints it to the investor and takes the investment. The investment is then split between the Mogul Bank and CO Reserve in accordance with the reserver ratio. More info on Reserve ration and reserves here: [https://github.com/C-ORG/whitepaper](https://github.com/C-ORG/whitepaper) 

#### Sell
`function sell(uint256 _amountMGL)` is the function used for selling MGL to the CO. It can only be called when the CO is LIVE or CLOSED and has one parameter:

- _amountMGL - the amount of MGL you want to sell

This function has a set gasPrice to be called with in order to avoid front-running.

Once this function is called and the different sanity checks are performed the sell function checks whether the state of the function is LIVE or CLOSED. The following description is the workings of the contract in the LIVE state. The function asks the Bonding Mathematics contract to calculate how much USD needs to be returned and sends it back to the user, while burning the specified MGL amount from the user balance.


#### Pay Dividends
`function payDividends(uint256 dividendAmount, uint8 dividendRatio)  public onlyWhenLive` is the function used for sending dividends back to the CO. It can only be called when the CO is LIVE and has two parameters:
- dividendAmount - how much USD are being paid back to the CO
- dividendRatio - the ratio between how much of the dividend is left in the reserve and how much goes in the investment fund (mogul bank)


#### Closing Organization
`function closeOrganisation() public onlyOwner onlyWhenLive` is the function used for closing the CO. It can only be triggered by the organization owner when the CO is live.

This function calculates a fee that needs to be paid by the owner for closing the CO. After this function finishes successfully the CO will transition to CLOSED state.

### Closed
This is the state triggered by the admin calling the closeOrganisation function. In this period only one function can be called - sell.

#### Sell
`function sell(uint256 _amountMGL)` is the function used for selling MGL to the CO.

While in CLOSED state the sell function will return the USD to the seller proportionally to their balance. You will receive the % of the reserve that corresponds to the % of MGL you own. After this the MGL is burned.

## Notes and Comments

### Movement Notification and Holding restriction
In order to ensure that the MGL token can only be hold by whitelisted addresses the MogulToken contract is an augmented version of ERC-20. This contract is supplying a hook functions for other contracts to "hook to". Through these functions the CO contract is notified for desired movement or sell and can perform and approve/deny the movement in accordance with the whitelist status of the receiver.
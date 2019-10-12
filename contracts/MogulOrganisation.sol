pragma solidity ^0.5.4;

import "./Tokens/MogulToken/MogulToken.sol";
import "./Tokens/MogulUSD/MogulUSD.sol";
import "./Math/BondingMathematics.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "./Helpers/Whitelisting.sol";


contract MogulOrganisation is Whitelisting, MovementNotifier {

    using SafeMath for uint256;
    
    BondingMathematics public bondingMath;

    MogulUSD public mogulUSD;
    MogulToken public mogulToken;

    address public mogulBank;
    address public mogulOrgAdmin;
    
    uint256 public premintedMGL = 0;
    
    uint256 constant public USD_RESERVE_REMAINDER = 5; // 20%
    
    uint16 public maxGasPrice = 30;
    
    uint8 constant public commissionPercentage = 2;
    
    enum State {
        LOCKED,
        LIVE,
        CLOSED
    }
    
    State public mogulOrgState;
    
    /*
    * Modifiers
    */
    modifier onlyWhenLive() {
        require(mogulOrgState == State.LIVE, "onlyWhenLive :: The Organisation iis not live");
        _;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == mogulOrgAdmin, "onlyAdmin :: msg sender is not the admin");
        _;
    }
    
    /*
    * Events
    */
    event Invest(address investor, uint256 amount);
    event Withdraw(address investor, uint256 amount);
    event UnlockOrganisation(address unlocker, uint256 initialAmount, uint256 initialMglSupply);
    event DividendPayed(address payer, uint256 amount);
    event CloseOrganisation(uint256 taxPenalty);
    
    /*
    * @dev Contract Constructor
    *
    * @param _bondingMath Address of contract calculating bonding mathematics based on sqrt
    * @param _mogulUSD Address of USD Token
    * @param _mogulToken Address of Mogul Token
    * @param _mogulBank Address of Mogul Bank
    * @param _whiteLister Address of Mogul whiteLister
    */
    constructor(address _bondingMath, address _mogulUSD, address _mogulToken, address _mogulBank, address _whiteLister) Whitelisting(_whiteLister) public {
        
        require(_mogulUSD != address(0), "constructor:: Mogul USD address is required");
        require(_mogulBank != address(0), "constructor:: Mogul Bank address is required");
        require(_bondingMath != address(0), "constructor:: Bonding Math address is required");

        mogulToken = MogulToken(_mogulToken);
        mogulUSD = MogulUSD(_mogulUSD);

        mogulBank = _mogulBank;
        mogulOrgAdmin = msg.sender;
        bondingMath = BondingMathematics(_bondingMath);
    }
    
    /*
    * @dev function setMaxGasPrice - Fixed transaction gas price preventing Front-Running attacks
    */
    function setMaxGasPrice(uint16 _maxGasPrice) public onlyAdmin {
        require(_maxGasPrice > 0, "setMaxGasPrice :: gas price can not be zero");
        maxGasPrice = _maxGasPrice;
    }
    
    /*
    * @dev function setMogulOrgAdminAddress - Possibility to change contract administrator address
    */
    function setMogulOrgAdminAddress(address _newMogulOrgAdmin) public onlyAdmin {
        require(_newMogulOrgAdmin != address(0), "mogulOrgAdminAddress :: invalid address");
        mogulOrgAdmin = _newMogulOrgAdmin;
    }
    
    /**
    * @dev function invest - Allows investors to invest in Mogul Tokens. The amount of received tokens is calculated based ot bonding mathematics
    *
    * @param usdAmount uint256 The amount of invested USD Tokens
    * @param signedData bytes Hash that should be signed from the whitelister wallet
    */
    function invest(uint256 usdAmount, bytes memory signedData) public onlyWhenLive {
        require(tx.gasprice == maxGasPrice);
        require(mogulUSD.balanceOf(address(this)) > 0, "invest:: Organisation is not unlocked for investments yet");
        require(mogulUSD.allowance(msg.sender, address(this)) >= usdAmount, "invest:: Investor tries to invest with unapproved USD amount");
        
        if (!whiteList[msg.sender]) {
            require(confirmedByManager(signedData));
            _setWhitelisted(msg.sender, true);
        }

        uint256 mglTokensToMint = calcRelevantMGLForUSD(usdAmount);

        uint256 commission = mglTokensToMint.mul(commissionPercentage).div(100);
        
        uint256 reserveUSDAmount = usdAmount.div(USD_RESERVE_REMAINDER);
        mogulUSD.transferFrom(msg.sender, address(this), reserveUSDAmount);
        mogulUSD.transferFrom(msg.sender, mogulBank, usdAmount.sub(reserveUSDAmount));

        mogulToken.mint(msg.sender, mglTokensToMint);
        mogulToken.mint(mogulOrgAdmin, commission);
        
        emit Invest(msg.sender, usdAmount);
    }
    
    /*
    * @dev function revokeInvestment Allows investors to sell their Mogul Tokens
    *
    * @param _amountMGL uint256 The amount of Mogul Tokens investor wants to sell
    */
    function sell(uint256 _amountMGL) public {
        require(tx.gasprice == maxGasPrice);
        require(mogulToken.allowance(msg.sender, address(this)) >= _amountMGL, "revokeInvestment:: Investor wants to withdraw MGL without allowance");
    
        uint256 usdToReturn = calcUSDToReturn(_amountMGL);
    
        mogulUSD.transfer(msg.sender, usdToReturn);
        mogulToken.burnFrom(msg.sender, _amountMGL);
    
        emit Withdraw(msg.sender, usdToReturn);
    }
    
    function calcUSDToReturn(uint256 _amountMGL) public view returns(uint256){
        if (mogulOrgState == State.LIVE) {
            return bondingMath.calcTokenSell(mogulToken.totalSupply(), mogulUSD.balanceOf(address(this)), _amountMGL);
        } else if(mogulOrgState == State.CLOSED) {
            return mogulUSD.balanceOf(address(this)).mul(_amountMGL).div(mogulToken.totalSupply());
        }
    }
    
    /*
    * @dev function calcRelevantMGLForUSD Uses bonding mathematics to calculate Mogul Tokens purchase
    *
    * @param usdAmount uint256 USD used to buy Mogul Tokens
    */
    function calcRelevantMGLForUSD(uint256 usdAmount) public view returns(uint256) {
        uint256 tokensAfterPurchase = bondingMath.calcPurchase(mogulToken.totalSupply(), premintedMGL, usdAmount);
        return tokensAfterPurchase;
    }
    
    /*
    * @dev function calcRelevantUSDForMGL Uses bonding mathematics to calculate Mogul Tokens sell
    *
    * @param coTokenAmount uint256 Mogul tokens to sell
    */
    function calcRelevantUSDForMGL(uint256 coTokenAmount) public view returns(uint256) {
        return bondingMath.calcTokenSell(mogulToken.totalSupply(), mogulUSD.balanceOf(address(this)), coTokenAmount);
    }
    
    /*
    * @dev function payDividends Allows to send dividends back to the Mogul bank and CO reserve increasing the mogul Token price
    *
    * @param dividendAmount uint256 USD Token amount payed back
    * @param dividendRatio uint8 The rate that tokens should be split between Mogul Bank and CO reserve
    */
    function payDividends(uint256 dividendAmount, uint8 dividendRatio)  public onlyWhenLive {
        require(dividendRatio <= 100, "dividendRatio is higher than maximum allowed");
        require(mogulUSD.balanceOf(address(this)) > 0, "payDividends:: Organisation is not unlocked for dividends payment yet");
        require(mogulUSD.allowance(msg.sender, address(this)) >= dividendAmount, "payDividends:: payer tries to pay with unapproved amount");
        
        uint256 reserveAmount = (dividendAmount.mul(dividendRatio)).div(100);
        
        mogulUSD.transferFrom(msg.sender, address(this), reserveAmount);
        mogulUSD.transferFrom(msg.sender, mogulBank, dividendAmount.sub(reserveAmount));
        
        emit DividendPayed(msg.sender, dividendAmount);
    }
    
    /*
    * @dev function unlockOrganisation initiate Continuous organisation
    *
    * @param organiserUSDContribution USD amount
    * @param organiserMGLReward initial Mogul Tokens supply
    */
    function unlockOrganisation(uint256 organiserUSDContribution, uint256 organiserMGLReward) public onlyOwner {
        require(mogulOrgState == State.LOCKED);
        require(mogulUSD.balanceOf(address(this)) == 0, "unlockOrganisation:: Organization is already unlocked");
        require(mogulUSD.allowance(msg.sender, address(this)) >= organiserUSDContribution, "unlockOrganisation:: Unlocker tries to unlock with unapproved amount");

        mogulUSD.transferFrom(msg.sender, address(this), organiserUSDContribution.div(USD_RESERVE_REMAINDER));
        mogulUSD.transferFrom(msg.sender, mogulBank, organiserUSDContribution.sub(organiserUSDContribution.div(USD_RESERVE_REMAINDER)));

        premintedMGL = organiserMGLReward;
        
        mogulToken.mint(msg.sender, organiserMGLReward);
    
        _setWhitelisted(msg.sender, true);
    
        mogulOrgState = State.LIVE;
        
        emit UnlockOrganisation(msg.sender, organiserUSDContribution, organiserMGLReward);
    }
    
    /*
    * @dev function closeOrganisation Cancels the CO and allows investors to restore their investments
    */
    function closeOrganisation() public onlyOwner onlyWhenLive {
        uint256 taxPenalty = calcCloseTaxPenalty();
        
        require(mogulUSD.allowance(msg.sender, address(this)) >= taxPenalty, "closeOrganisation :: Owner tries to close organisation with unapproved USD amount");

        mogulUSD.transferFrom(msg.sender, address(this), taxPenalty);

        mogulOrgState = State.CLOSED;

        emit CloseOrganisation(taxPenalty);
    }
    
    /*
    * @dev function calcCloseTaxPenalty Returns closing tax in USD
    */
    function calcCloseTaxPenalty() public view returns(uint256) {
        return bondingMath.calcExitFee(mogulToken.totalSupply(), premintedMGL, mogulUSD.balanceOf(address(this)));
    }
    
    /*
    * @dev function onTransfer Token movement notifier implementation
    */
    function onTransfer(address from, address to, uint256 value) external {
        require(whiteList[to]);
    }
    
    /*
    * @dev onBurn onTransfer Token movement notifier implementation
    */
    function onBurn(address from, uint256 value) external {
        require(whiteList[from]);
    }
    
}

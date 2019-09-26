pragma solidity ^0.5.3;

import "./../Math/Convert.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";


contract Voting is Ownable {
    
    using Convert for bytes;
    using SafeMath for uint256;

    IERC20 public daiTokenContract;
    IERC20 public mogulTokenContract;
    address public sqrtContract;
    uint256 public lastVotingDate = 0;
    uint256 public currentRound = 0;
    
    struct Round {
        uint256 startDate;
        uint256 endDate;
        uint8 proposalCount;
        mapping (uint8 => Proposal) proposals;
        mapping (address => uint8) votedFor;
        uint256 maxInvestment;
    }
    
    struct Proposal {
        bytes32 name;
        mapping (address => uint256) voterToVotes;
        uint256 totalVotes;
        address sponsorshipReceiver;
        uint256 requestedAmount;
    }
    
    Round[] public rounds;
    
    /*
    * Events
    */
    event RoundCreated(uint256 indexed roundID, uint8 proposalsCount, uint256 startDate, uint256 endDate);
    event Voted(uint256 indexed roundID, address voter, uint8 propolsalID);
    event RoundFinalized(uint256 indexed roundID, uint8 winnerID);
    event CancelRound(uint256 indexed roundID);
    
    modifier onlyTokenAddress() {
        require(msg.sender == address(mogulTokenContract), "movementNotifier :: permission denied");
        _;
    }
    
    /*
    * @dev Contract Constructor
    *
    * @param _mogulTokenAddress Address of Mogul Token
    * @param _daiTokenInstance Address of DAI Token
    * @param _sqrtContract Address of sqrt calculations contract
    */
    constructor(address _mogulTokenAddress, address _daiTokenInstance, address _sqrtContract) public {
        require(_sqrtContract != address(0), "constructor :: SQRT contract could not be an empty address");
        require(_mogulTokenAddress != address(0), "constructor :: Mogul token contract could not be an empty address");
        require(_daiTokenInstance != address(0), "constructor :: Mogul DAI token contract could not be an empty address");
        
        mogulTokenContract = IERC20(_mogulTokenAddress);
        daiTokenContract = IERC20(_daiTokenInstance);
        sqrtContract = _sqrtContract;
    }
    
    /*
    * @dev function createRound Allows Voting Contract Admin to create voting round with set of movies
    *
    * @param _movieNames array of bytes32 movie names
    * @param _sponsorshipReceiver array of addresses of fund receivers
    * @param _requestedAmount array of uint256 of requested sponsorship amounts
    * @param _startDate uint256 round start date
    * @param _expirationDate uint256 round end date
    */
    function createRound(
        bytes32[] memory _movieNames,
        address[] memory _sponsorshipReceiver,
        uint256[] memory _requestedAmount,
        uint256 _startDate,
        uint256 _expirationDate
    ) public onlyOwner {
        require(_startDate >= now, "createRound :: Start date cannot be in the past");
        require(_expirationDate > _startDate, "createRound :: Start date cannot be after expiration date");
        require(_startDate > lastVotingDate, "createRound :: Start date must be after last voting date");
        require(_movieNames.length > 1, "createRound :: There should be at least two movies");
        require(_movieNames.length == _sponsorshipReceiver.length
            && _sponsorshipReceiver.length == _requestedAmount.length, "createRound :: proposals data count is different");
            uint256 largestInvestment = getLargestInvestment(_requestedAmount);
        
        daiTokenContract.transferFrom(msg.sender, address(this), largestInvestment);
        
        lastVotingDate = _expirationDate;
    
        Round memory currentRoundData = Round({
            proposalCount: uint8(_movieNames.length),
            startDate: _startDate,
            endDate: _expirationDate,
            maxInvestment: largestInvestment
            });
        
        rounds.push(currentRoundData);
        
        for(uint8 i = 0; i < _movieNames.length; i++){

            Proposal memory currentProposal = Proposal({

            name: _movieNames[i],
            totalVotes: 0,
            sponsorshipReceiver: _sponsorshipReceiver[i],
            requestedAmount: _requestedAmount[i]

        });
            rounds[rounds.length - 1].proposals[i] = currentProposal;
        }
        
        emit RoundCreated(rounds.length - 1, rounds[rounds.length - 1].proposalCount, _startDate, _expirationDate);
    }
    
    /*
    * @dev function vote allows investor to vote for specific movie
    *
    * @param _movieId uint8 Movie id
    */
    function vote(uint8 _movieId) public {
        uint8 movieNumber = _movieId + 1;
        require(now >= rounds[currentRound].startDate && now <= rounds[currentRound].endDate, "vote :: now is not within a voting period for this round");
        require(rounds[currentRound].votedFor[msg.sender] == 0 || rounds[currentRound].votedFor[msg.sender] == movieNumber, "vote :: user is not allowed to vote more than once");
        require(rounds[currentRound].proposalCount > _movieId, "vote :: there is no such movie id in this round");
        
        if (rounds[currentRound].votedFor[msg.sender] == movieNumber) {
            rounds[currentRound].proposals[_movieId].totalVotes = rounds[currentRound].proposals[_movieId].totalVotes.sub(rounds[currentRound].proposals[_movieId].voterToVotes[msg.sender]);
        }
        
        uint256 voterMogulBalance = mogulTokenContract.balanceOf(msg.sender);
        uint256 rating = __calculateRatingByTokens(voterMogulBalance.mul(10));
        
        rounds[currentRound].proposals[_movieId].voterToVotes[msg.sender] = rating;
        rounds[currentRound].proposals[_movieId].totalVotes = rounds[currentRound].proposals[_movieId].totalVotes.add(rating);
        
        // we are using the first element /0/ for empty votes
        rounds[currentRound].votedFor[msg.sender] = movieNumber;
        
        emit Voted(currentRound, msg.sender, _movieId);
    }
    
    /*
    * @dev function finalizeRound allows contract admin to finalize an ended round
    */
    function finalizeRound() public {
        require(rounds[currentRound].endDate < now, "finalizeRound :: the round is not finished");

        uint256 mostVotes;
        uint8 winnerMovieIndex;

        for(uint8 i = 0; i < rounds[currentRound].proposalCount; i++) {
            if(mostVotes < rounds[currentRound].proposals[i].totalVotes) {
                mostVotes = rounds[currentRound].proposals[i].totalVotes;
                winnerMovieIndex = i;
            }
        }

        uint256 remainingDAI = (rounds[currentRound].maxInvestment).sub(rounds[currentRound].proposals[winnerMovieIndex].requestedAmount);

        daiTokenContract.transfer(rounds[currentRound].proposals[winnerMovieIndex].sponsorshipReceiver, rounds[currentRound].proposals[winnerMovieIndex].requestedAmount);
        if(remainingDAI > 0) {
            daiTokenContract.transfer(owner(), remainingDAI);
        }

        currentRound++;
    }
    
    /*
    * @dev function cancelRound allows contract admin to cancel a round
    */
    function cancelRound() public onlyOwner {
        require(currentRound < rounds.length);
        
        daiTokenContract.transfer(owner(), rounds[currentRound].maxInvestment);
        
        emit CancelRound(currentRound);
    
        currentRound++;
    }
    
    /*
    * @dev function onTransfer Token movement notifier implementation
    * if one transfer Mogul Tokens his vote is canceled
    */
    function onTransfer(address from, address to, uint256 value) public onlyTokenAddress {
        if (rounds.length > 0) {
            if (rounds[currentRound].votedFor[from] != 0
            && rounds[currentRound].startDate <= now
            && rounds[currentRound].endDate >= now) {
                __revokeVote(from);
            }
        }
    }
    
    /*
    * @dev function onBurn Token movement notifier implementation
    * if one sell Mogul Tokens his vote is canceled
    */
    function onBurn(address from, uint256 value) public onlyTokenAddress {
        if (rounds.length > 0) {
            if (rounds[currentRound].votedFor[from] != 0
            && rounds[currentRound].startDate <= now
            && rounds[currentRound].endDate >= now) {
                __revokeVote(from);
            }
        }
    }
    
    /*
    * @dev function getRoundInfo returns given round info
    *
    * @param _round given round by index
    *
    * @returns round startDate, endDate, proposalCount, maxInvestment (largest investment request)
    */
    function getRoundInfo(uint256 _round) public view returns (uint256, uint256, uint8, uint256){
        return (rounds[_round].startDate, rounds[_round].endDate, rounds[_round].proposalCount, rounds[_round].maxInvestment);
    }
    
    /*
    * @dev function getRounds returns rounds count
    */
    function getRounds() public view returns (uint256){
        return rounds.length;
    }
    
    /*
    * @dev function getProposalInfo returns proposal info
    *
    * @param _round uint256 given round by index
    * @param _proposal uint8 given proposal by index
    *
    * @returns proposal (movie) name, totalVotes, sponsorshipReceiver address, requestedAmount
    */
    function getProposalInfo(uint256 _round, uint8 _proposal) public view returns (bytes32, uint256, address, uint256){
        return (rounds[_round].proposals[_proposal].name,
        rounds[_round].proposals[_proposal].totalVotes,
        rounds[_round].proposals[_proposal].sponsorshipReceiver,
        rounds[_round].proposals[_proposal].requestedAmount);
    }
    
    /*
    * @dev function getVotersVotesInfo returns the votes that a voter has given
    *
    * @param _round uint256 given round by index
    * @param _proposal uint8 given proposal by index
    * @param _voter address the address of the voter
    *
    * @returns the number of votes that a voter has given
    */
    function getVotersVotesInfo(uint256 _round, uint8 _proposal, address _voter) public view returns (uint256){
        return rounds[_round].proposals[_proposal].voterToVotes[_voter];
    }
    
    /*
    * @dev function getVoteInfo returns proposal on which voters voted
    *
    * @param _round uint256 given round by index
    * @param _voter address the address of the voter
    *
    * @returns proposal on which voters voted
    */
    function getVoteInfo(uint256 _round, address _voterAddress) public view returns (uint8){
        return (rounds[_round].votedFor[_voterAddress]);
    }
    
    function getLargestInvestment(uint256[] memory _requestedAmounts) private pure returns(uint256) {
        
        uint256 largestInvestment;
        
        for (uint8 i = 0; i < _requestedAmounts.length; i++) {
            if (largestInvestment < _requestedAmounts[i]) {
                largestInvestment = _requestedAmounts[i];
            }
        }
        return largestInvestment;
    }
    
    // Rating is calculated as => sqrt(voter tokens balance) => 1 token = 1 rating; 9 tokens = 3 rating
    function __calculateRatingByTokens(uint256 tokens) private view returns(uint256){
        // Call a Vyper SQRT contract in order to work with decimals in sqrt
        (bool success, bytes memory data) = sqrtContract.staticcall(abi.encodeWithSignature("tokens_sqrt(uint256)", tokens));
        require(success);
        
        uint rating = data.toUint256();
        return rating;
    }
    
    /*
    * @dev function __revokeVote Cancels investors vote
    *
    * @param from address The address which votes will be canceled
    */
    function __revokeVote(address from) private {
        
        uint8 proposalIndex = rounds[currentRound].votedFor[from] - 1;
        uint256 votes = rounds[currentRound].proposals[proposalIndex].voterToVotes[from];
    
        rounds[currentRound].proposals[proposalIndex].totalVotes = rounds[currentRound].proposals[proposalIndex].totalVotes.sub(votes);
        rounds[currentRound].proposals[proposalIndex].voterToVotes[from] = 0;
        rounds[currentRound].votedFor[from] = 0;
    }
}

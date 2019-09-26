const etherlime = require('etherlime-lib');
const calculationHelper = require('./utils/token-price-calculation');

const ContractInitializator = require('./utils/contract-initializator');

describe('Voting Contract', function () {

    this.timeout(20000);

    const provider = new ethers.providers.JsonRpcProvider();

    const sevenDays = 604800;
    const oneDay = 86400;

    const OWNER = accounts[0].signer;
    const INVESTOR = accounts[9].signer;


    const ONE_DAI = ethers.utils.bigNumberify("1000000000000000000");
    const MILLION_DAI = ONE_DAI.mul("1000000");

    const SPONSORSHIP_RECEIVER_1 = accounts[2].signer;
    const SPONSORSHIP_RECEIVER_2 = accounts[3].signer;
    const SPONSORSHIP_RECEIVER_3 = accounts[4].signer;
    const SPONSORSHIP_RECEIVER_4 = accounts[5].signer;
    const SPONSORSHIP_RECEIVER_5 = accounts[6].signer;

    const today = new Date();

    const MOVIE_NAMES = [
        ethers.utils.formatBytes32String('Godzilla king of the monsters'),
        ethers.utils.formatBytes32String('History of the world'),
        ethers.utils.formatBytes32String('Die hard'),
        ethers.utils.formatBytes32String('Bruce almighty'),
        ethers.utils.formatBytes32String('Ted')
    ];

    const MOVIE_SPONSORSHIP_RECEIVER = [
        SPONSORSHIP_RECEIVER_1.address,
        SPONSORSHIP_RECEIVER_2.address,
        SPONSORSHIP_RECEIVER_3.address,
        SPONSORSHIP_RECEIVER_4.address,
        SPONSORSHIP_RECEIVER_5.address
    ];

    const MOVIE_REQUESTED_AMOUNT = [
        MILLION_DAI,
        MILLION_DAI.mul('2'),
        MILLION_DAI.mul('3'),
        MILLION_DAI.mul('4'),
        MILLION_DAI.mul('5')
    ];

    const ONE_ETH = ethers.utils.bigNumberify("1000000000000000000");
    const INVESTMENT_AMOUNT = ONE_ETH.mul(100000);
    const UNLOCK_AMOUNT = ONE_ETH.mul(2500000);
    const INITIAL_MOGUL_SUPPLY = ONE_ETH.mul(5000000);

    const MAX_GAS_PRICE = 30;

    let votingContract;

    let mogulDAIInstance;
    let mogulOrganisationInstance;
    let mogulTokenContract;

    let startDate;
    let endDate;

    function hashData(wallet, data) {
        const hashMsg = ethers.utils.solidityKeccak256(['address'], [data]);
        const hashData = ethers.utils.arrayify(hashMsg);
        return wallet.signMessage(hashData);
    }

    const signedData = hashData(OWNER, INVESTOR.address);

    describe('Initialization', function () {

        beforeEach(async () => {
            mogulTokenContract = await ContractInitializator.deployMogulToken();
            mogulDAIInstance = await ContractInitializator.deployMglDai();

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);
        });

        it('Should initialize the contract correctly', async () => {
            let owner = await votingContract.owner();
            let _mogulTokenInstance = await votingContract.mogulTokenContract();

            assert.strictEqual(owner, OWNER.address);
            assert.strictEqual(_mogulTokenInstance, mogulTokenContract.contractAddress);

        });

    });

    describe('Proposing', function () {

        beforeEach(async () => {
            mogulTokenContract = await ContractInitializator.deployMogulToken();
            mogulDAIInstance = await ContractInitializator.deployMglDai();

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);
            await mogulDAIInstance.mint(OWNER.address, MILLION_DAI.mul('5'));
            await mogulDAIInstance.approve(votingContract.contractAddress, MILLION_DAI.mul('5'));

            const blockInfo = await provider.getBlock();
            startDate = blockInfo.timestamp + oneDay;
            endDate = startDate + sevenDays;

        });

        it('Should make a proposal correctly', async () => {
            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate,{
                gasLimit: 2700000
            });

            let lastVotingDate = await votingContract.lastVotingDate();
            assert(lastVotingDate.eq(endDate));

            let roundInfo = await votingContract.getRoundInfo(0);

            let rounds = await votingContract.getRounds();
            let expectedRounds = 1;

            assert(rounds.eq(expectedRounds));
            assert(roundInfo[0].eq(startDate));
            assert(roundInfo[1].eq(endDate));
            assert.strictEqual(roundInfo[2], MOVIE_NAMES.length);

            for (let i = 0; i < roundInfo[2]; i++) {
                let proposalInfo = await votingContract.getProposalInfo(0, i);
                assert.strictEqual(proposalInfo[0], MOVIE_NAMES[i]);
                assert.strictEqual(proposalInfo[2], MOVIE_SPONSORSHIP_RECEIVER[i]);
                assert(proposalInfo[3].eq(MOVIE_REQUESTED_AMOUNT[i]));
            }
        });

        it('Should revert if start date is after end date', async () => {
            await assert.revert(votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, endDate, startDate, {
                gasLimit: 2700000
            }));
        });

        it('Should revert if start date is in the past', async () => {
            let dateInPast = endDate = Math.floor(today.setDate(today.getDate() - 30) / 1000);
            await assert.revert(votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, dateInPast, endDate, {
                gasLimit: 2700000
            }));
        });

        it('Should revert if start date is before last voting date', async () => {
            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            });
            let dateDuringVotingPeriod = endDate = Math.floor(today.setDate(today.getDate() + 15) / 1000);
            await assert.revert(votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, dateDuringVotingPeriod, endDate, {
                gasLimit: 2700000
            }));
        });

        it('Should revert if movie names are less than other properties', async () => {

            const LESS_MOVIE_NAMES = [
                '0x4d6f766965320000000000000000000000000000000000000000000000000000',
                '0x4d6f766965330000000000000000000000000000000000000000000000000000',
                '0x4d6f766965340000000000000000000000000000000000000000000000000000',
                '0x4d6f766965350000000000000000000000000000000000000000000000000000'
            ];
            await assert.revert(votingContract.createRound(LESS_MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            }));
        });

        it('Should revert if sponsorship receivers are less or more than other properties', async () => {

            const MORE_MOVIE_SPONSORSHIP_RECEIVER = [
                SPONSORSHIP_RECEIVER_1.address,
                SPONSORSHIP_RECEIVER_2.address,
                SPONSORSHIP_RECEIVER_3.address,
                SPONSORSHIP_RECEIVER_4.address,
                SPONSORSHIP_RECEIVER_5.address,
                accounts[6].signer.address,
            ];

            await assert.revert(votingContract.createRound(MOVIE_NAMES, MORE_MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            }));
        });

        it('Should revert if movie descriptions are less or more than other properties', async () => {

            const MORE_MOVIE_REQUESTED_AMOUNT = [
                MILLION_DAI,
                MILLION_DAI.mul('2'),
                MILLION_DAI.mul('3'),
                MILLION_DAI.mul('4'),
                MILLION_DAI.mul('5'),
                MILLION_DAI.mul('6')
            ];
            await assert.revert(votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MORE_MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            }));
        });

    });

    describe('Voting', function () {

        beforeEach(async () => {

            mogulDAIInstance = await ContractInitializator.deployMglDai();
            mogulOrganisationInstance = await ContractInitializator.deployMogulOrganization(mogulDAIInstance);
            mogulTokenContract = await ContractInitializator.getMogulToken(mogulOrganisationInstance, OWNER);

            await ContractInitializator.mintDAI(mogulDAIInstance, OWNER.address, UNLOCK_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, OWNER, mogulOrganisationInstance.contractAddress, UNLOCK_AMOUNT);


            await ContractInitializator.mintDAI(mogulDAIInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

            await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                gasLimit: 2000000
            });

            await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                gasPrice: MAX_GAS_PRICE,
                gasLimit: 2700000
            });

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);

            const blockInfo = await provider.getBlock();
            startDate = blockInfo.timestamp + oneDay;
            endDate = startDate + sevenDays;

            await mogulDAIInstance.mint(OWNER.address, MILLION_DAI.mul('5'));
            await mogulDAIInstance.approve(votingContract.contractAddress, MILLION_DAI.mul('5'));

            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            });

            await mogulTokenContract.addMovementNotifier(votingContract.contractAddress);

            await utils.setTimeTo(provider, startDate);
        });

        it('Should vote correctly', async () => {

            await votingContract.from(INVESTOR).vote(0);

            let voteInfo = await votingContract.getVoteInfo(0, INVESTOR.address);

            //we are expecting movie index of 1 because we are giving the 0 index to empty votes
            let expectedMovie = 1;
            assert.strictEqual(voteInfo, expectedMovie, "the vote is not given to the first movie");

            let proposalInfo = await votingContract.getProposalInfo(0, 0);
            let voterVoteInfo = await votingContract.getVotersVotesInfo(0, 0, INVESTOR.address);

            let investorMogulTokens = await mogulTokenContract.balanceOf(INVESTOR.address);
            let expectedRating = calculationHelper.sqrtTokens(investorMogulTokens.mul(10));

            assert.strictEqual(proposalInfo[1].toString().substring(0, 10), expectedRating.toString());
            assert.strictEqual(voterVoteInfo.toString().substring(0, 10), expectedRating.toString());
        });

        it('Should allow voter to vote again for the same movie and recalculate his vote weight correctly', async () => {

            await votingContract.from(INVESTOR).vote(0);

            await ContractInitializator.mintDAI(mogulDAIInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

            await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                gasPrice: MAX_GAS_PRICE,
                gasLimit: 2700000
            });

            await votingContract.from(INVESTOR).vote(0);

            let voteInfo = await votingContract.getVoteInfo(0, INVESTOR.address);

            //we are expecting movie index of 1 because we are giving the 0 index to empty votes
            let expectedMovie = 1;
            assert.strictEqual(voteInfo, expectedMovie, "the vote is not given to the first movie");

            let proposalInfo = await votingContract.getProposalInfo(0, 0);

            let investorMogulTokens = await mogulTokenContract.balanceOf(INVESTOR.address);
            let expectedRating = calculationHelper.sqrtTokens(investorMogulTokens.mul(10));

            assert.strictEqual(proposalInfo[1].toString().substring(0, 10), expectedRating.toString());
        });

        it('Should revert if one tries to change his vote', async () => {
            await votingContract.from(INVESTOR).vote(0);
            await assert.revert(votingContract.from(INVESTOR).vote(2));
        });

        it('Should revert if one tries to vote outside voting period', async () => {
            await utils.setTimeTo(provider, endDate + 1);
            await assert.revert(votingContract.from(INVESTOR).vote(1));
        });

        it('Should revert if one tries to vote to non-existing movie id', async () => {
            await assert.revert(votingContract.from(INVESTOR).vote(5));
        });

    });

    describe('Finalizing', function () {

        beforeEach(async () => {

            mogulDAIInstance = await ContractInitializator.deployMglDai();
            mogulOrganisationInstance = await ContractInitializator.deployMogulOrganization(mogulDAIInstance);
            mogulTokenContract = await ContractInitializator.getMogulToken(mogulOrganisationInstance, OWNER);

            await ContractInitializator.mintDAI(mogulDAIInstance, OWNER.address, UNLOCK_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, OWNER, mogulOrganisationInstance.contractAddress, UNLOCK_AMOUNT);

            await ContractInitializator.mintDAI(mogulDAIInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

            await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                gasLimit: 2000000
            });

            await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                gasPrice: MAX_GAS_PRICE,
                gasLimit: 2700000
            });

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);

            const blockInfo = await provider.getBlock();
            startDate = blockInfo.timestamp + oneDay;
            endDate = startDate + sevenDays;

            await mogulDAIInstance.mint(OWNER.address, MILLION_DAI.mul('5'));
            await mogulDAIInstance.approve(votingContract.contractAddress, MILLION_DAI.mul('5'));

            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            });

            await utils.setTimeTo(provider, startDate);

            await votingContract.from(INVESTOR).vote(0);
        });

        it('Should finalize correctly', async () => {
            let winnerMovieSponsorship = MILLION_DAI;
            let largestMovieSponsorship = MILLION_DAI.mul(5);
            let sponsorshipReceiverBefore = await mogulDAIInstance.balanceOf(SPONSORSHIP_RECEIVER_1.address);

            await utils.setTimeTo(provider, endDate + 1);
            await votingContract.finalizeRound();

            let sponsorshipReceiverAfter = await mogulDAIInstance.balanceOf(SPONSORSHIP_RECEIVER_1.address);
            let ownerBalanceAfter = await mogulDAIInstance.balanceOf(OWNER.address);

            assert(sponsorshipReceiverAfter.eq(sponsorshipReceiverBefore.add(winnerMovieSponsorship)));
            assert(ownerBalanceAfter.eq(largestMovieSponsorship.sub(winnerMovieSponsorship)));

            let currentRound = await votingContract.currentRound();
            assert(currentRound.eq(1));

        });

        it('Should not allow to finalize round within voting period', async () => {
            await assert.revert(votingContract.finalizeRound());
        });
    });

    describe('Revoke Vote', function () {

        beforeEach(async () => {

            mogulDAIInstance = await ContractInitializator.deployMglDai();
            mogulOrganisationInstance = await ContractInitializator.deployMogulOrganization(mogulDAIInstance);
            mogulTokenContract = await ContractInitializator.getMogulToken(mogulOrganisationInstance, OWNER);

            await ContractInitializator.mintDAI(mogulDAIInstance, OWNER.address, UNLOCK_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, OWNER, mogulOrganisationInstance.contractAddress, UNLOCK_AMOUNT);

            await ContractInitializator.mintDAI(mogulDAIInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

            await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                gasLimit: 2000000
            });

            await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                gasPrice: MAX_GAS_PRICE,
                gasLimit: 2700000
            });
            await mogulOrganisationInstance.setWhitelisted(OWNER.address, true);

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);
            await mogulTokenContract.addMovementNotifier(votingContract.contractAddress);

            const blockInfo = await provider.getBlock();
            startDate = blockInfo.timestamp + oneDay;
            endDate = startDate + sevenDays;

            await mogulDAIInstance.mint(OWNER.address, MILLION_DAI.mul('5'));
            await mogulDAIInstance.approve(votingContract.contractAddress, MILLION_DAI.mul('5'));

            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            });

            await utils.setTimeTo(provider, startDate);

            await votingContract.from(INVESTOR.address).vote(0);
        });

        it('Should revoke vote if one sell mogul tokens', async () => {
            let investorMglTokens = await mogulTokenContract.balanceOf(INVESTOR.address);

            await mogulTokenContract.from(INVESTOR.address).approve(mogulOrganisationInstance.contractAddress, investorMglTokens);
            await mogulOrganisationInstance.from(INVESTOR.address).sell(investorMglTokens, {
                gasPrice: MAX_GAS_PRICE
            });

            let votes = await votingContract.getVotersVotesInfo(0, 0, INVESTOR.address);
            let voteInfo = await votingContract.getVoteInfo(0, INVESTOR.address);
            let roundInfo = await votingContract.getProposalInfo(0, 0);

            assert(votes.eq(0));
            assert.strictEqual(voteInfo, 0);
            assert(roundInfo[1].eq(0));

        });

        it('Should revoke vote if one call transferFrom', async () => {
            let investorMglTokens = await mogulTokenContract.balanceOf(INVESTOR.address);

            await mogulTokenContract.from(INVESTOR.address).approve(OWNER.address, investorMglTokens);
            await mogulTokenContract.from(OWNER.address).transferFrom(INVESTOR.address, OWNER.address, investorMglTokens);

            let votes = await votingContract.getVotersVotesInfo(0, 0, INVESTOR.address);
            let voteInfo = await votingContract.getVoteInfo(0, INVESTOR.address);
            let roundInfo = await votingContract.getProposalInfo(0, 0);

            assert(votes.eq(0));
            assert.strictEqual(voteInfo, 0);
            assert(roundInfo[1].eq(0));
        });

        it('Should revert if other than token contract tries to call onTransfer', async () => {
            await assert.revert(votingContract.onTransfer(INVESTOR.address, OWNER.address, 0));
        });

        it('Should revert if other than token contract tries to call onBurn', async () => {
            await assert.revert(votingContract.onBurn(INVESTOR.address, 0));
        });

    });

    describe('Cancel Round', function () {

        beforeEach(async () => {

            mogulDAIInstance = await ContractInitializator.deployMglDai();
            mogulOrganisationInstance = await ContractInitializator.deployMogulOrganization(mogulDAIInstance);
            mogulTokenContract = await ContractInitializator.getMogulToken(mogulOrganisationInstance, OWNER);

            await ContractInitializator.mintDAI(mogulDAIInstance, OWNER.address, UNLOCK_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, OWNER, mogulOrganisationInstance.contractAddress, UNLOCK_AMOUNT);

            await ContractInitializator.mintDAI(mogulDAIInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await ContractInitializator.approveDAI(mogulDAIInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

            await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                gasLimit: 2000000
            });

            await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                gasPrice: MAX_GAS_PRICE,
                gasLimit: 2700000
            });
            await mogulOrganisationInstance.setWhitelisted(OWNER.address, true);

            votingContract = await ContractInitializator.getVotingContract(mogulTokenContract.contractAddress, mogulDAIInstance.contractAddress);
            await mogulTokenContract.addMovementNotifier(votingContract.contractAddress);

            const blockInfo = await provider.getBlock();
            startDate = blockInfo.timestamp + oneDay;
            endDate = startDate + sevenDays;

            await mogulDAIInstance.mint(OWNER.address, MILLION_DAI.mul('5'));
            await mogulDAIInstance.approve(votingContract.contractAddress, MILLION_DAI.mul('5'));

            await votingContract.createRound(MOVIE_NAMES, MOVIE_SPONSORSHIP_RECEIVER, MOVIE_REQUESTED_AMOUNT, startDate, endDate, {
                gasLimit: 2700000
            });

            await utils.setTimeTo(provider, startDate);

            await votingContract.from(INVESTOR.address).vote(1);
        });

        it('Should cancel round and move to next one', async () => {
            let currentRound = await votingContract.currentRound();

            let roundMaxInvestment = await votingContract.getRoundInfo(0);

            await votingContract.cancelRound();

            let roundAfterCancel = await votingContract.currentRound();

            let ownerBalance = await mogulDAIInstance.balanceOf(OWNER.address);

            assert.strictEqual(roundMaxInvestment[3].toString, ownerBalance.toString);
            assert(currentRound.add(1).eq(roundAfterCancel));
        });

        it('Should revert if one tries to cancel not started round', async () => {
            await votingContract.cancelRound();
            await assert.revert(votingContract.cancelRound());
        });

        it('Should revert if not owner tries to cancel round', async () => {
            await assert.revert(votingContract.from(INVESTOR.address).cancelRound());
        });

    });

});

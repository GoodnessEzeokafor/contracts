const etherlime = require('etherlime-lib');

const MogulUSD = require('./../../build/MogulUSD');
const MogulToken = require('./../../build/MogulToken');

const SQRT = require('./../../build/BondingCurveCalculations');
const TokensSQRT = require('./../../build/QuadraticVotingCalculations');
const BondingMathematics = require('./../../build/BondingMathematics');

const MogulOrganisation = require('./../../build/MogulOrganisation');

const Voting = require('../../build/Voting');

const deployerWallet = accounts[0].signer;
const WHITELISTER = accounts[0].signer.address;
const MOGUL_BANK = accounts[9].signer.address;

const deployer = new etherlime.EtherlimeGanacheDeployer();
deployer.setDefaultOverrides({ gasLimit: 6700000, gasPrice: 9000000000 });


let deployMogulOrganization = async (mglDai) => {

    let bondingMathematicsInstance = await deployBondingMath();
    const mogulToken = await deployMogulToken();

    const mglOrganisationInstance = await deployer.deploy(MogulOrganisation, {},
        bondingMathematicsInstance.contractAddress,
        mglDai.contractAddress,
        mogulToken.contractAddress,
        MOGUL_BANK,
        WHITELISTER);

    await mogulToken.addMinter(mglOrganisationInstance.contractAddress);
    await mogulToken.renounceMinter();

    await mogulToken.addMovementNotifier(mglOrganisationInstance.contractAddress);

    return mglOrganisationInstance;
};

let deploySQRT = async () => {
    return deployer.deploy(SQRT);
};

let deployTokenSQRT = async () => {
    return deployer.deploy(TokensSQRT, {});
};

let getMogulToken = async (mogulOrganisationInstance, wallet) => {
    let mogulTokenAddress = await mogulOrganisationInstance.mogulToken();
    return  etherlime.ContractAt(MogulToken, mogulTokenAddress, wallet);

};

let deployMogulToken = async () => {
    return deployer.deploy(MogulToken, {});
};

let deployBondingMath = async () => {
    let sqrtContractAddress = await deploySQRT(deployerWallet);
    return deployer.deploy(BondingMathematics, {}, sqrtContractAddress.contractAddress);
};

let deployMglDai = async () => {
    return deployer.deploy(MogulUSD);
};

let mintDAI = async (mogulDAIInstance, to, amount) => {
    await mogulDAIInstance.mint(to, amount)
};

let approveDAI = async (mogulDAIInstance, approver, to, amount) => {
    await mogulDAIInstance.from(approver).approve(to, amount)
};

let getVotingContract = async (mogulTokenAddress, mogulDAIAddress) => {
    const sqrtContract = await deployer.deploy(TokensSQRT);
    return await deployer.deploy(Voting, {}, mogulTokenAddress, mogulDAIAddress, sqrtContract.contractAddress);

};

module.exports = {
    getMogulToken,
    mintDAI,
    approveDAI,
    deployMogulOrganization,
    deployMglDai,
    deployTokenSQRT,
    deployMogulToken,
    getVotingContract
};

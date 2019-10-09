const etherlime = require('etherlime-lib');
const { buyCalc, sellCalc } = require('./utils/token-price-calculation');
const contractInitializator = require('./utils/contract-initializator');
const ethers = require('ethers');


describe('Mogul Organisation Contract', function () {

    this.timeout(20000);
    const OWNER = accounts[0].signer;
    const INVESTOR = accounts[1].signer;
    const REPAYER = accounts[2].signer;
    const MOGUL_BANK = accounts[9].signer.address;

    const DIVIDEND_RATIO = 20;

    const ONE_ETH = ethers.utils.bigNumberify("1000000000000000000");
    const normalization = ethers.utils.bigNumberify("1000000000000000000");

    const INVESTMENT_AMOUNT = ONE_ETH.mul(100000);
    const UNLOCK_AMOUNT = ONE_ETH.mul(2500000);
    const DOUBLE_AMOUNT = UNLOCK_AMOUNT.mul(2);

    const INITIAL_MOGUL_SUPPLY = ONE_ETH.mul(5000000);

    const MAX_GAS_PRICE = 30;

    let mogulUSDInstance;
    let mogulTokenInstance;

    let mogulOrganisationInstance;

    function hashData(wallet, data) {
        const hashMsg = ethers.utils.solidityKeccak256(['address'], [data]);
        const hashData = ethers.utils.arrayify(hashMsg);
        return wallet.signMessage(hashData);
    }

    function toHumanReadableValue(wei) {

        return wei.toString().match(/^-?\d+(?:\.\d{0,4})?/)[0]
    }


    describe('Continuous Organisation Contract', function () {

        beforeEach(async () => {
            mogulUSDInstance = await contractInitializator.deployMglDai();

            mogulOrganisationInstance = await contractInitializator.deployMogulOrganization(mogulUSDInstance);

            mogulTokenInstance = await contractInitializator.getMogulToken(mogulOrganisationInstance, OWNER);

            // Mint and Approve 1 ETH in order to unlock the organization
            await contractInitializator.mintDAI(mogulUSDInstance, OWNER.address, UNLOCK_AMOUNT);
            await contractInitializator.approveDAI(mogulUSDInstance, OWNER, mogulOrganisationInstance.contractAddress, UNLOCK_AMOUNT);


            // await approveUSD(INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);
            await contractInitializator.mintDAI(mogulUSDInstance, INVESTOR.address, INVESTMENT_AMOUNT);
            await contractInitializator.approveDAI(mogulUSDInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

        });

        describe('Movement Notifier', function () {

            it('should return MovementNotifier implementation count', async () => {
                let movementNotifiersCount = await mogulTokenInstance.getMovementNotifiersCount();
                assert.strictEqual(movementNotifiersCount.toString(), "1")
            });

            it('should add MovementNotifier implementation address', async () => {
                let newNotifierImpl = accounts[8].signer;

                await mogulTokenInstance.addMovementNotifier(newNotifierImpl.address);

                let movementNotifiersCount = await mogulTokenInstance.getMovementNotifiersCount();
                let lastAddedAddress = await mogulTokenInstance.movementNotifiers(movementNotifiersCount - 1);
                assert.strictEqual(lastAddedAddress, newNotifierImpl.address)
            });

            it('should NOT add MovementNotifier implementation address if not from owner', async () => {
                mogulTokenInstance = await contractInitializator.getMogulToken(mogulOrganisationInstance, INVESTOR);
                let newNotifierImpl = accounts[8].signer;

                await assert.revert(mogulTokenInstance.addMovementNotifier(newNotifierImpl.address));
            });

            it('should remove from MovementNotifier implementation array', async () => {
                let movementNotifiersCount = await mogulTokenInstance.getMovementNotifiersCount();
                await mogulTokenInstance.removeMovementNotifier(movementNotifiersCount -1);

                let movementNotifiersCountAfter = await mogulTokenInstance.getMovementNotifiersCount();
                assert.strictEqual(movementNotifiersCountAfter.toString(), (movementNotifiersCount - 1).toString())
            });

            it('should NOT remove from MovementNotifier implementation array if not from owner', async () => {
                mogulTokenInstance = await contractInitializator.getMogulToken(mogulOrganisationInstance, INVESTOR);

                let movementNotifiersCount = await mogulTokenInstance.getMovementNotifiersCount();
                await assert.revert(mogulTokenInstance.removeMovementNotifier(movementNotifiersCount -1));
            });

        });

        describe('Unlocking and Initialization', function () {

            it('Should unlock the organisation', async () => {
                let expectedBalance = UNLOCK_AMOUNT.div(5); // 20%
                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                let organisationBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                let ownerMglBalance = await mogulTokenInstance.balanceOf(OWNER.address);

                let unlockedState = 1;
                let state = await mogulOrganisationInstance.mogulOrgState();

                assert.strictEqual(unlockedState, state, "the state is not unlocked");
                assert(ownerMglBalance.eq(INITIAL_MOGUL_SUPPLY), 'Owner balance is incorrect after unlocking');
                assert(organisationBalance.eq(expectedBalance), 'Organisation balance is incorrect after unlocking');
            });

            it('Should throw on re-unlocking', async () => {
                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                await assert.revert(mogulOrganisationInstance.unlockOrganisation(ONE_ETH, INITIAL_MOGUL_SUPPLY), 'Re-unlocking of an organisation did not throw');
            });

            it('Should throw if an unlocker tries to unlock with unapproved USD amount', async () => {
                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                await assert.revert(mogulOrganisationInstance.unlockOrganisation(DOUBLE_AMOUNT, INITIAL_MOGUL_SUPPLY), 'Organisation has been unlocked with unapproved USD amount');
            });

            it('Should throw if one tries to invest in non-unlocked organisation', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(ONE_ETH, signedData, {
                    gasPrice: MAX_GAS_PRICE
                }), 'An investment has been processed for a non-unlocked organisation');
            });

            it('Should set mogul organisation admin correctly', async () => {
                const adminAddress = await mogulOrganisationInstance.mogulOrgAdmin();
                assert.strictEqual(adminAddress, OWNER.address, "mogul admin is not set correctly");
            });

            it('Should change mogul organisation admin', async () => {
                await mogulOrganisationInstance.setMogulOrgAdminAddress(INVESTOR.address);
                const newAdminAddress = await mogulOrganisationInstance.mogulOrgAdmin();

                assert.strictEqual(newAdminAddress, INVESTOR.address, "mogul admin is not changed correctly");
            });

            it('Should change max gas price', async () => {
                const NEW_PRICE = 60;
                await mogulOrganisationInstance.setMaxGasPrice(NEW_PRICE);
                let newGasPrice = await mogulOrganisationInstance.maxGasPrice();
                assert.strictEqual(newGasPrice, NEW_PRICE, "Gas prise was not changed correctly");
            });

            it('Should revert if not admin tries to change max gas price', async () => {
                const NEW_PRICE = 60;
                await assert.revert(mogulOrganisationInstance.from(INVESTOR).setMaxGasPrice(NEW_PRICE));
            });

            it('Should revert if not admin tries to change mogul organisation admin', async () => {
                await assert.revert(mogulOrganisationInstance.from(INVESTOR).setMogulOrgAdminAddress(INVESTOR.address));
            });
        });

        describe('Investment', function () {
            let signedData;
            beforeEach(async () => {
                signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });

            });

            it('should calculate investment correctly', async () => {
                const amount = await mogulOrganisationInstance.from(INVESTOR).calcRelevantMGLForUSD(INVESTMENT_AMOUNT);
                const EXPECTED_INVESTOR_MOGUL_BALANCE = buyCalc(INITIAL_MOGUL_SUPPLY, INITIAL_MOGUL_SUPPLY, INVESTMENT_AMOUNT);
                assert.strictEqual(toHumanReadableValue(ethers.utils.formatEther(amount)), toHumanReadableValue(Number(EXPECTED_INVESTOR_MOGUL_BALANCE / normalization).toFixed(10)))
            });

            it('should send 2% of the received MGL to mogul wallet', async () => {
                let commissionPercentage = 2;
                let ownerMogulBalance = await mogulTokenInstance.balanceOf(OWNER.address);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                let investorMogulBalance = await mogulTokenInstance.balanceOf(INVESTOR.address);
                let commissionMGL = investorMogulBalance.mul(commissionPercentage).div(100);

                let expectedOwnerBalance = ownerMogulBalance.add(commissionMGL);

                let ownerMogulBalanceAfter = await mogulTokenInstance.balanceOf(OWNER.address);

                assert(ownerMogulBalanceAfter.eq(expectedOwnerBalance), 'Incorrect calculation of 2% MGL commission');

            });

            it('should send correct usd amount to the mogul bank', async () => {
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                const EXPECTED_BANK_BALANCE = UNLOCK_AMOUNT.add(INVESTMENT_AMOUNT).div(5).mul(4); // 80%
                let bankBalance = await mogulUSDInstance.balanceOf(MOGUL_BANK);
                assert(bankBalance.eq(EXPECTED_BANK_BALANCE), 'Incorrect bank balance after investment');
            });

            it('should send correct usd amount to the reserve', async () => {
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                const EXPECTED_RESERVE_BALANCE = UNLOCK_AMOUNT.add(INVESTMENT_AMOUNT).div(5); // 0.4 ETH (Unlocking + investment)
                let reserveBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                assert(reserveBalance.eq(EXPECTED_RESERVE_BALANCE), 'Incorrect reserve balance after investment');
            });

            it('should send correct amount mogul tokens to the investor', async () => {
                // normalization is because of 18 decimals of mogul token
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                const EXPECTED_INVESTOR_MOGUL_BALANCE = (buyCalc(INITIAL_MOGUL_SUPPLY, INITIAL_MOGUL_SUPPLY, INVESTMENT_AMOUNT) / normalization).toFixed(9);
                let investorMogulBalance = await mogulTokenInstance.balanceOf(INVESTOR.address);
                investorMogulBalance = (Number(investorMogulBalance.toString()) / normalization).toFixed(9);

                assert.strictEqual(investorMogulBalance, EXPECTED_INVESTOR_MOGUL_BALANCE, 'Incorrect investor mogul balance after investment');
            });

            it('Should receive correct invest amount', async () => {
                // EXPECTED_INVESTMENTS_AMOUNT = 80% of unlocking amount + investment amount
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                const EXPECTED_INVESTMENTS_AMOUNT = (UNLOCK_AMOUNT.add(INVESTMENT_AMOUNT)).mul(80).div(100);
                let totalUSDInvestments = await mogulUSDInstance.balanceOf(MOGUL_BANK);

                assert(totalUSDInvestments.eq(EXPECTED_INVESTMENTS_AMOUNT), 'Incorrect investments amount after investment');
            });

            it('Should throw if an investor tries to invest with unapproved USD amount', async () => {
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                let investorWithoutUSD = accounts[3].signer;

                const signedData2 = hashData(OWNER, investorWithoutUSD.address);

                await assert.revert(mogulOrganisationInstance.from(investorWithoutUSD).invest(ONE_ETH, signedData2, {
                    gasPrice: MAX_GAS_PRICE
                }), 'An investment has been processed with unapproved USD amount');
            });

        });

        describe('Whitelist validations', function () {

            beforeEach(async () => {
                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
            });

            it('Should change whiteLister', async () => {
                const newWhiteLister = accounts[5].signer.address;

                await mogulOrganisationInstance.setManager(newWhiteLister);
                const newWhiteListerFromContract = await mogulOrganisationInstance.manager();

                assert.strictEqual(newWhiteListerFromContract, newWhiteLister, "WhiteLister is not changed correctly");
            });

            it('Should let new whitelister to whitelist user', async () => {
                const newWhiteLister = accounts[5].signer;
                await mogulOrganisationInstance.setManager(newWhiteLister.address);

                const signedData = hashData(newWhiteLister, INVESTOR.address);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                const isWhitelisted = await mogulOrganisationInstance.whiteList(INVESTOR.address);
                assert.ok(isWhitelisted);

            });

            it('Should not allow old admin to whitelist users', async () => {
                const newWhiteLister = accounts[5].signer;
                await mogulOrganisationInstance.setManager(newWhiteLister.address);

                const signedData = hashData(OWNER, INVESTOR.address);

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                }));

            });

            it('Should throw on trying to change whitelister not from owner', async () => {
                const newWhiteLister = accounts[5].signer.address;
                await assert.revert(mogulOrganisationInstance.from(INVESTOR).setManager(newWhiteLister), 'Changing whiteLister not from owner did not throw');
            });

            it('Should let investor to invest and save him as whitelisted if approved from owner / whitelister', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                const isWhitelisted = await mogulOrganisationInstance.whiteList(INVESTOR.address);
                assert.ok(isWhitelisted);
            });

            it('Should let whitelisted investor to invest', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                const isWhitelisted = await mogulOrganisationInstance.whiteList(INVESTOR.address);
                assert.ok(isWhitelisted);

                await contractInitializator.mintDAI(mogulUSDInstance, INVESTOR.address, INVESTMENT_AMOUNT);
                await contractInitializator.approveDAI(mogulUSDInstance, INVESTOR, mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, ethers.constants.AddressZero, {
                    gasPrice: MAX_GAS_PRICE
                });
            });

            it('Should let whitelister to manual whitelist user', async () => {
                const newWhiteListed = accounts[5].signer;
                await mogulOrganisationInstance.setWhitelisted(newWhiteListed.address, true);

                const isWhitelisted = await mogulOrganisationInstance.whiteList(newWhiteListed.address);
                assert.ok(isWhitelisted);
            });

            it('Should let whitelister to remove whitelist user', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
                await mogulOrganisationInstance.from(OWNER).setWhitelisted(INVESTOR.address, false);

                const isWhitelisted = await mogulOrganisationInstance.whiteList(INVESTOR.address);
                assert.ok(!isWhitelisted);
            });

            it('Should let one to transfer MGL tokens to whitelisted user', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                await mogulTokenInstance.approve(INVESTOR.address, ONE_ETH);
                await mogulTokenInstance.transfer(INVESTOR.address, ONE_ETH);
            });

            it('Should revert if one tries to transfer MGL tokens to non whitelisted useer', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                await mogulTokenInstance.approve(INVESTOR.address, ONE_ETH);
                await mogulOrganisationInstance.from(OWNER).setWhitelisted(INVESTOR.address, false);
                await assert.revert(mogulTokenInstance.transfer(INVESTOR.address, ONE_ETH));
            });

            it('Should revert if not whitelister tries to manage manually whitelisted', async () => {
                await assert.revert(mogulOrganisationInstance.from(INVESTOR).setWhitelisted(INVESTOR.address, true));
            });

            it('Should revert if not whitelisted investor try to invest', async () => {
                const emptySignedData = "0x";

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, emptySignedData, {
                    gasPrice: MAX_GAS_PRICE
                }));
            });

            it('Should revert if one try to invest with incorrect signature', async () => {
                const signedData = hashData(INVESTOR, INVESTOR.address);

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                }));
            });

        });

        describe('Revoke Investment', function () {

            beforeEach(async () => {
                mogulTokenInstance = await contractInitializator.getMogulToken(mogulOrganisationInstance, INVESTOR);
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });
            });

            it('Should sell MGL Tokens for ~ 80% less of their buying price', async () => {
                let mglTokens = await mogulTokenInstance.balanceOf(INVESTOR.address);

                let organisationMogulBalance = await mogulTokenInstance.totalSupply();
                let reserveBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                let expectedUsd = sellCalc(organisationMogulBalance, reserveBalance, mglTokens);

                await mogulTokenInstance.approve(mogulOrganisationInstance.contractAddress, mglTokens);
                await mogulOrganisationInstance.from(INVESTOR).sell(mglTokens, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                });


                let usdBalance = await mogulUSDInstance.balanceOf(INVESTOR.address);

                let normalizedUSDBalance = (usdBalance / normalization).toFixed(4);
                let expectedBalance = (expectedUsd / normalization).toFixed(4);

                assert.strictEqual(toHumanReadableValue(normalizedUSDBalance), toHumanReadableValue(expectedBalance));
            });

            it('Should sell MGL Tokens on profit after some investments', async () => {
                let mglTokens = await mogulTokenInstance.balanceOf(INVESTOR.address);

                let randomInvestment = "40000000000000000000";
                await contractInitializator.mintDAI(mogulUSDInstance, OWNER.address, randomInvestment);
                await mogulUSDInstance.from(OWNER).approve(mogulOrganisationInstance.contractAddress, randomInvestment);

                const signedData = hashData(OWNER, OWNER.address);

                await mogulOrganisationInstance.from(OWNER).invest(randomInvestment, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                await mogulTokenInstance.approve(mogulOrganisationInstance.contractAddress, mglTokens);
                await mogulOrganisationInstance.from(INVESTOR).sell(mglTokens, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                });

                let usdBalance = await mogulUSDInstance.balanceOf(INVESTOR.address);

                let normUsdBalance = (usdBalance / normalization).toFixed(6);

                assert(1 <= normUsdBalance, "tokens are not sold on profit");
            });

            it('Should revert if one tries to sell unapproved tokens', async () => {
                let tokens = "414213562299999999";
                await assert.revert(mogulOrganisationInstance.from(INVESTOR).sell(tokens, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                }));

            });

            it("Should revert if one tries to sell tokens that he doesn't have", async () => {
                let tokens = "414213562299999999";
                await assert.revert(mogulOrganisationInstance.from(OWNER).sell(tokens, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                }));
            });
        });

        describe('Paying dividends', function () {

            beforeEach(async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });

                await contractInitializator.mintDAI(mogulUSDInstance, REPAYER.address, ONE_ETH);
                await contractInitializator.approveDAI(mogulUSDInstance, REPAYER.address, mogulOrganisationInstance.contractAddress, ONE_ETH);
            });

            it('Should lower COToken returned on investment after paying dividends', async () => {

                let mglTokens = await mogulTokenInstance.balanceOf(INVESTOR.address);

                const coTokensPerInvestmentBefore = await mogulOrganisationInstance.calcRelevantUSDForMGL(mglTokens);

                await mogulOrganisationInstance.from(REPAYER).payDividends(ONE_ETH, DIVIDEND_RATIO);

                const coTokensPerInvestmentAfter = await mogulOrganisationInstance.calcRelevantUSDForMGL(mglTokens);

                assert(coTokensPerInvestmentAfter.gt(coTokensPerInvestmentBefore), "The token sell price after dividents repayment were not increased")
            });

            it('Should receive more USD on COToken exit after paying dividends', async () => {

                let coTokens = await mogulTokenInstance.balanceOf(INVESTOR.address);


                const USDReturnedForInvestmentBefore = await mogulOrganisationInstance.calcRelevantUSDForMGL(coTokens);

                await mogulOrganisationInstance.from(REPAYER).payDividends(ONE_ETH, DIVIDEND_RATIO);

                await mogulTokenInstance.approve(mogulOrganisationInstance.contractAddress, coTokens);
                await mogulOrganisationInstance.from(INVESTOR).calcRelevantUSDForMGL(coTokens);

                const USDReturnedForInvestmentAfter = await mogulOrganisationInstance.calcRelevantUSDForMGL(coTokens);

                assert(USDReturnedForInvestmentAfter.gt(USDReturnedForInvestmentBefore), "The USD received after exit was not more than before dividents payout")
            });

            it('Should allocate dividends correctly between mogul bank and CO', async () => {

                let coBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                let mogulBankBalance = await mogulUSDInstance.balanceOf(MOGUL_BANK);

                let coPart = ONE_ETH.mul(DIVIDEND_RATIO).div(100);

                let expectedCOBalance = coBalance.add(coPart); // coBalance + 20%
                let expectedMogulBankBalance = mogulBankBalance.add(ONE_ETH.sub(coPart)); // mogulBankBalance + 20%

                await mogulOrganisationInstance.from(REPAYER).payDividends(ONE_ETH, DIVIDEND_RATIO);

                let newCoBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                let newMogulBankBalance = await mogulUSDInstance.balanceOf(MOGUL_BANK);

                assert.strictEqual(expectedCOBalance.toString(), newCoBalance.toString());
                assert.strictEqual(expectedMogulBankBalance.toString(), newMogulBankBalance.toString());
            });

            it('Should allocate dividends correctly between mogul bank and CO whit 100% dividend ratio', async () => {
                const newDividendRatio = 100;
                let coBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                let mogulBankBalance = await mogulUSDInstance.balanceOf(MOGUL_BANK);

                let coPart = ONE_ETH.mul(newDividendRatio).div(100);

                let expectedCOBalance = coBalance.add(coPart); // coBalance + 20%
                let expectedMogulBankBalance = mogulBankBalance.add(ONE_ETH.sub(coPart)); // mogulBankBalance + 20%

                await mogulOrganisationInstance.from(REPAYER).payDividends(ONE_ETH, newDividendRatio);

                let newCoBalance = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);
                let newMogulBankBalance = await mogulUSDInstance.balanceOf(MOGUL_BANK);

                assert.strictEqual(expectedCOBalance.toString(), newCoBalance.toString());
                assert.strictEqual(expectedMogulBankBalance.toString(), newMogulBankBalance.toString());
            });

            it('Should revert if one tries to pay dividends whit higher than 100% ratio', async () => {
                const higherRatio = 101;
                await assert.revert(mogulOrganisationInstance.from(REPAYER).payDividends(ONE_ETH, higherRatio));
            });

            it('Should revert if one tries to repay with unapproved USD', async () => {
                await contractInitializator.mintDAI(mogulUSDInstance, REPAYER.address, ONE_ETH);
                await assert.revert(mogulOrganisationInstance.from(REPAYER).payDividends(DOUBLE_AMOUNT, DIVIDEND_RATIO));
            });

            it("Should revert if one tries to repay USD that he doesn't have", async () => {
                await assert.revert(mogulOrganisationInstance.from(REPAYER).payDividends(DOUBLE_AMOUNT, DIVIDEND_RATIO));
            });
        });

        // taxPenalty = ((totalMGLSupply^2 / preMintedMGLAmount)/2) - buyback_reserve
        describe('Closing Mogul c-org', function () {

            beforeEach(async () => {
                const signedData = hashData(OWNER, INVESTOR.address);

                await mogulOrganisationInstance.unlockOrganisation(UNLOCK_AMOUNT, INITIAL_MOGUL_SUPPLY, {
                    gasLimit: 2000000
                });
                await mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                });


            });

            it('Should close Mogul c-org', async () => {
                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                const isClosedState = 2;
                let state = await mogulOrganisationInstance.mogulOrgState();
                assert.strictEqual(state, isClosedState);
            });

            it('Should revert if not owner tries to close', async () => {
                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).closeOrganisation());
            });

            it('Should revert if one tries to close with less USD', async () => {
                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const lessTaxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve).div(2);

                await mogulUSDInstance.mint(OWNER.address, lessTaxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, lessTaxPenalty);

                await assert.revert(mogulOrganisationInstance.closeOrganisation());
            });

            it('Should revert if one tries to invest after closing the c-org', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);
                await mogulUSDInstance.mint(INVESTOR.address, INVESTMENT_AMOUNT);
                await mogulUSDInstance.from(INVESTOR).approve(mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                }));
            });

            it('Should revert if one tries to invest after closing the c-org', async () => {
                const signedData = hashData(OWNER, INVESTOR.address);
                await mogulUSDInstance.mint(INVESTOR.address, INVESTMENT_AMOUNT);
                await mogulUSDInstance.from(INVESTOR).approve(mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                await assert.revert(mogulOrganisationInstance.from(INVESTOR).invest(INVESTMENT_AMOUNT, signedData, {
                    gasPrice: MAX_GAS_PRICE
                }));
            });

            it('Should revert if one tries to pay dividends after closing the c-org', async () => {
                await mogulUSDInstance.mint(REPAYER.address, INVESTMENT_AMOUNT);
                await mogulUSDInstance.from(REPAYER).approve(mogulOrganisationInstance.contractAddress, INVESTMENT_AMOUNT);

                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                await assert.revert(mogulOrganisationInstance.from(REPAYER).payDividends(INVESTMENT_AMOUNT, DIVIDEND_RATIO));
            });

            it('Should revert if one tries to close a closed c-org', async () => {

                const totalMglSupply = await mogulTokenInstance.totalSupply();
                const usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                await assert.revert(mogulOrganisationInstance.closeOrganisation());
            });

            it('Should revoke investments correctly after closing the c-org', async () => {

                const totalMglSupply = await mogulTokenInstance.totalSupply();
                let usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                const taxPenalty = totalMglSupply.mul(totalMglSupply).div(INITIAL_MOGUL_SUPPLY).div(2).sub(usdReserve);

                await mogulUSDInstance.mint(OWNER.address, taxPenalty);
                await mogulUSDInstance.approve(mogulOrganisationInstance.contractAddress, taxPenalty);

                await mogulOrganisationInstance.closeOrganisation();

                let mglTokens = await mogulTokenInstance.balanceOf(INVESTOR.address);

                await mogulTokenInstance.from(INVESTOR.address).approve(mogulOrganisationInstance.contractAddress, mglTokens);
                await mogulOrganisationInstance.from(INVESTOR).sell(mglTokens, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                });

                let ownerMGL = await mogulTokenInstance.balanceOf(OWNER.address);


                await mogulTokenInstance.approve(mogulOrganisationInstance.contractAddress, ownerMGL);

                await mogulOrganisationInstance.sell(ownerMGL, {
                    gasPrice: MAX_GAS_PRICE,
                    gasLimit: 250000
                });

                let mogulTokens = await mogulTokenInstance.totalSupply();
                usdReserve = await mogulUSDInstance.balanceOf(mogulOrganisationInstance.contractAddress);

                assert(mogulTokens.eq(0));
                assert(usdReserve.eq(0));
            });

        });
    });
});

require('dotenv').config();
const axios = require('axios');
const { ethers } = require('ethers');
const blessed = require('blessed');
const colors = require('colors');
const fs = require('fs');
const { HttpsProxyAgent } = require('https-proxy-agent');

const API_BASE_URL = 'https://sowing-api.taker.xyz';
const CONTRACT_ADDRESS = '0xF929AB815E8BfB84Cdab8d1bb53F22eB1e455378';
const CONTRACT_ABI = [
    {
        "constant": false,
        "inputs": [],
        "name": "active",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    }
];

const HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json',
    'sec-ch-ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'Referer': 'https://sowing.taker.xyz/',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
};

// Максимальное количество повторных попыток для API-запросов
const MAX_RETRIES = 3;
// Время ожидания между повторными попытками (в мс)
const RETRY_DELAY = 2000;
// Экспоненциальный коэффициент для увеличения времени ожидания
const BACKOFF_FACTOR = 1.5;

// Загрузка прокси
const proxies = fs.existsSync('proxies.txt')
    ? fs.readFileSync('proxies.txt', 'utf-8')
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
    : [];
if (proxies.length === 0) {
    console.warn('No proxies found in proxies.txt. Running without proxies.');
}

// Загрузка приватных ключей и создание кошельков
const wallets = [];
for (let i = 1; ; i++) {
    const key = process.env[`PRIVATE_KEY_${i}`];
    if (!key) break;
    try {
        const wallet = new ethers.Wallet(key);
        wallets.push({
            privateKey: key,
            address: wallet.address,
            proxy: proxies.length > 0 ? proxies[Math.floor(Math.random() * proxies.length)] : null,
            retryCount: 0,  // Счетчик повторных попыток для этого кошелька
            lastError: null, // Последняя ошибка для этого кошелька
            status: 'initializing', // Текущий статус кошелька: 'initializing', 'farming', 'completed', 'error'
            lastSuccessfulRequest: Date.now(), // Время последнего успешного запроса
        });
    } catch (error) {
        console.error(`Invalid PRIVATE_KEY_${i}: ${error.message}`);
    }
}
if (wallets.length === 0) {
    throw new Error('No valid private keys found in .env file');
}

// Настройка UI с blessed
const screen = blessed.screen({
    smartCSR: true,
    title: 'Taker Farming Bot'
});

const headerBox = blessed.box({
    top: 0,
    left: 0,
    width: '100%',
    height: 3,
    content: '{center}SOWING TAKER FARMING BOT - AIRDROP INSIDERS{/center}',
    tags: true,
    style: { fg: 'cyan', bg: 'black' }
});

const modeBox = blessed.box({
    top: 3,
    left: 0,
    width: '100%',
    height: 3,
    content: `{center}CURRENT MODE: {green-fg}AUTO-FARMING{/green-fg} | Wallet 1 of ${wallets.length}{/center}`,
    tags: true,
    style: { fg: 'yellow', bg: 'black', border: { fg: 'white' } },
    border: { type: 'line' }
});

const userInfoBox = blessed.box({
    top: 6,
    left: 0,
    width: '100%',
    height: 7,
    content: 'Loading user info...',
    tags: true,
    style: { fg: 'white', bg: 'black', border: { fg: 'white' } },
    border: { type: 'line' }
});

const farmingStatusBox = blessed.box({
    top: 13,
    left: 0,
    width: '100%',
    height: 9,
    content: 'Loading farming status...',
    tags: true,
    style: { fg: 'white', bg: 'black', border: { fg: 'white' } },
    border: { type: 'line' }
});

const logBox = blessed.log({
    top: 22,
    left: 0,
    width: '100%',
    height: 60,
    content: '',
    tags: true,
    scrollable: true,
    mouse: true,
    style: { fg: 'white', bg: 'black', border: { fg: 'white' } },
    border: { type: 'line' },
    scrollbar: { ch: ' ', style: { bg: 'blue' } }
});

const statusBox = blessed.box({
    bottom: 0,
    left: 0,
    width: '100%',
    height: 3,
    content: '{center}Press [q] to Quit | [r] to Refresh Tokens | [←] Prev Wallet | [→] Next Wallet{/center}',
    tags: true,
    style: { fg: 'white', bg: 'black', border: { fg: 'white' } },
    border: { type: 'line' }
});

screen.append(headerBox);
screen.append(modeBox);
screen.append(userInfoBox);
screen.append(farmingStatusBox);
screen.append(logBox);
screen.append(statusBox);

let currentWalletIndex = 0;
const tokens = {};

// Улучшенная функция логирования
function logMessage(message, type = 'info', walletAddress = '') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = walletAddress ? `[${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}] ` : '';
    let coloredMessage;
    switch (type) {
        case 'error':
            coloredMessage = `{red-fg}[${timestamp}] ${prefix}${message}{/red-fg}`;
            break;
        case 'success':
            coloredMessage = `{green-fg}[${timestamp}] ${prefix}${message}{/green-fg}`;
            break;
        case 'warning':
            coloredMessage = `{yellow-fg}[${timestamp}] ${prefix}${message}{/yellow-fg}`;
            break;
        case 'retrying':
            coloredMessage = `{blue-fg}[${timestamp}] ${prefix}${message}{/blue-fg}`;
            break;
        default:
            coloredMessage = `{white-fg}[${timestamp}] ${prefix}${message}{/white-fg}`;
    }
    logBox.log(coloredMessage);
    screen.render();
    
    // Дополнительно записываем в лог-файл для удобства отладки
    try {
        const logDir = './logs';
        if (!fs.existsSync(logDir)){
            fs.mkdirSync(logDir);
        }
        const logDate = new Date().toISOString().split('T')[0];
        const logLine = `[${timestamp}] [${type.toUpperCase()}] ${prefix}${message}\n`;
        fs.appendFileSync(`${logDir}/taker-bot-${logDate}.log`, logLine);
    } catch (e) {
        // Игнорируем ошибки записи лога
    }
}

function normalizeProxy(proxy) {
    if (!proxy) return null;
    if (!proxy.startsWith('http://') && !proxy.startsWith('https://')) {
        proxy = `http://${proxy}`;
    }
    return proxy;
}

// Улучшенная функция sleep с промисами
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Улучшенная функция API-запроса с повторными попытками и обработкой ошибок
async function apiRequest(url, method = 'GET', data = null, authToken = null, proxy = null, retries = 0, wallet = null) {
    const config = {
        method,
        url,
        headers: { ...HEADERS },
        timeout: 30000, // 30 секунд таймаут для запросов
    };
    if (data) config.data = data;
    if (authToken) config.headers['authorization'] = `Bearer ${authToken}`;
    if (proxy) {
        config.httpsAgent = new HttpsProxyAgent(normalizeProxy(proxy));
    }
    
    try {
        const response = await axios(config);
        
        // Обновляем время последнего успешного запроса
        if (wallet) {
            wallet.lastSuccessfulRequest = Date.now();
            wallet.retryCount = 0; // Сбрасываем счетчик повторных попыток
        }
        
        return response.data;
    } catch (error) {
        const statusCode = error.response?.status;
        const errorMessage = error.response?.data?.message || error.message;
        
        // Увеличиваем счетчик повторных попыток кошелька
        if (wallet) {
            wallet.retryCount = (wallet.retryCount || 0) + 1;
            wallet.lastError = `${statusCode || 'Network'} Error: ${errorMessage}`;
        }
        
        // Обработка различных кодов HTTP-ошибок
        if (statusCode === 429) {
            // Too Many Requests - нужна повторная попытка с экспоненциальной задержкой
            const walletInfo = wallet ? `for wallet ${wallet.address.slice(0, 6)}...` : '';
            logMessage(`Rate limit exceeded ${walletInfo}. Waiting before retry...`, 'warning', wallet?.address);
            
            // Экспоненциальная задержка
            const delayTime = RETRY_DELAY * Math.pow(BACKOFF_FACTOR, retries);
            await sleep(delayTime);
            
            if (retries < MAX_RETRIES) {
                logMessage(`Retrying request (${retries + 1}/${MAX_RETRIES})...`, 'retrying', wallet?.address);
                return apiRequest(url, method, data, authToken, proxy, retries + 1, wallet);
            }
        } else if (statusCode >= 500) {
            // Ошибки сервера - тоже повторяем
            logMessage(`Server error ${statusCode}. Retrying...`, 'warning', wallet?.address);
            
            // Задержка перед повторной попыткой
            await sleep(RETRY_DELAY);
            
            if (retries < MAX_RETRIES) {
                logMessage(`Retrying request (${retries + 1}/${MAX_RETRIES})...`, 'retrying', wallet?.address);
                return apiRequest(url, method, data, authToken, proxy, retries + 1, wallet);
            }
        } else if (!statusCode && error.code === 'ECONNABORTED') {
            // Timeout - повторяем запрос
            logMessage(`Request timeout. Retrying...`, 'warning', wallet?.address);
            
            if (retries < MAX_RETRIES) {
                logMessage(`Retrying request (${retries + 1}/${MAX_RETRIES})...`, 'retrying', wallet?.address);
                return apiRequest(url, method, data, authToken, proxy, retries + 1, wallet);
            }
        } else if (!statusCode) {
            // Сетевые ошибки - проблемы с прокси или соединением
            logMessage(`Network error: ${error.message}. Check your connection or proxy.`, 'error', wallet?.address);
            
            // Попробуем без прокси или с другим прокси, если есть ошибка соединения
            if (proxy && retries < 1) {
                logMessage(`Retrying without proxy...`, 'retrying', wallet?.address);
                return apiRequest(url, method, data, authToken, null, retries + 1, wallet);
            } else if (retries < MAX_RETRIES) {
                await sleep(RETRY_DELAY);
                logMessage(`Retrying request (${retries + 1}/${MAX_RETRIES})...`, 'retrying', wallet?.address);
                return apiRequest(url, method, data, authToken, proxy, retries + 1, wallet);
            }
        } else if (statusCode === 401 || statusCode === 403) {
            // Проблемы с авторизацией
            logMessage(`Authentication error (${statusCode}): ${errorMessage}. Try refreshing token.`, 'error', wallet?.address);
            throw new Error(`Authentication failed: ${errorMessage}`);
        } else {
            // Другие ошибки
            logMessage(`API error ${statusCode || ''}: ${errorMessage}`, 'error', wallet?.address);
        }
        
        // Если все повторные попытки исчерпаны
        if (retries >= MAX_RETRIES) {
            logMessage(`All ${MAX_RETRIES} retry attempts failed. Giving up.`, 'error', wallet?.address);
        }
        
        throw new Error(errorMessage || 'API request failed');
    }
}

async function generateNonce(wallet) {
    try {
        wallet.status = 'generating nonce';
        const response = await apiRequest(
            `${API_BASE_URL}/wallet/generateNonce`,
            'POST',
            { walletAddress: ethers.utils.getAddress(wallet.address) }, 
            null,
            wallet.proxy,
            0,
            wallet
        );
        
        logMessage(`Nonce API response: ${JSON.stringify(response)}`, 'info', wallet.address); 
        
        if (response.code === 200) {
            if (response.result?.nonce) {
                return response.result.nonce; 
            } else if (typeof response.result === 'string') {
                const nonceMatch = response.result.match(/Nonce: (.*)$/m);
                if (nonceMatch && nonceMatch[1]) {
                    return nonceMatch[1];
                }
            }
        }
        throw new Error('Failed to parse nonce from response: ' + (response.message || 'Unknown error'));
    } catch (error) {
        wallet.status = 'error';
        wallet.lastError = `Nonce generation failed: ${error.message}`;
        throw new Error('Failed to generate nonce: ' + error.message);
    }
}

async function login(wallet, nonce) {
    try {
        wallet.status = 'logging in';
        const checksummedAddress = ethers.utils.getAddress(wallet.address);

        const message = `Taker quest needs to verify your identity to prevent unauthorized access. Please confirm your sign-in details below:\n\naddress: ${checksummedAddress}\n\nNonce: ${nonce}`;
        
        const ethersWallet = new ethers.Wallet(wallet.privateKey);

        logMessage(`Message to sign: ${message}`, 'info', wallet.address);

        let signature;
        try {
            signature = await ethersWallet.signMessage(message);
            logMessage(`Generated signature: ${signature}`, 'info', wallet.address);
        } catch (error) {
            logMessage(`Signature generation failed: ${error.message}`, 'error', wallet.address);
            throw error;
        }

        const response = await apiRequest(
            `${API_BASE_URL}/wallet/login`,
            'POST',
            { address: checksummedAddress, signature, message },
            null,
            wallet.proxy,
            0,
            wallet
        );

        logMessage(`Login API response: ${JSON.stringify(response)}`, 'info', wallet.address); 

        if (response.code === 200) {
            return response.result.token;
        }

        logMessage('Standard signature failed. Attempting EIP-712 signing...', 'warning', wallet.address);
        const domain = {
            name: 'Taker',
            version: '1',
            chainId: 1125, 
        };
        const types = {
            Login: [
                { name: 'address', type: 'address' },
                { name: 'nonce', type: 'string' },
            ],
        };
        const value = {
            address: checksummedAddress,
            nonce: nonce,
        };
        
        try {
            signature = await ethersWallet._signTypedData(domain, types, value);
            logMessage(`Generated EIP-712 signature: ${signature}`, 'info', wallet.address);
        } catch (error) {
            logMessage(`EIP-712 signature generation failed: ${error.message}`, 'error', wallet.address);
            throw error;
        }

        const eip712Response = await apiRequest(
            `${API_BASE_URL}/wallet/login`,
            'POST',
            { address: checksummedAddress, signature, message: JSON.stringify({ domain, types, value }) },
            null,
            wallet.proxy,
            0,
            wallet
        );

        logMessage(`EIP-712 login API response: ${JSON.stringify(eip712Response)}`, 'info', wallet.address);

        if (eip712Response.code === 200) {
            return eip712Response.result.token;
        }

        throw new Error('Login failed: ' + (response.message || eip712Response.message || 'Signature mismatch'));
    } catch (error) {
        wallet.status = 'error';
        wallet.lastError = `Login failed: ${error.message}`;
        throw error;
    }
}

async function getUserInfo(wallet, token) {
    try {
        if (!token) {
            throw new Error('No authentication token available');
        }
        
        const response = await apiRequest(
            `${API_BASE_URL}/user/info`,
            'GET',
            null,
            token,
            wallet.proxy,
            0,
            wallet
        );
        
        if (response.code === 200) {
            return response.result;
        }
        throw new Error('Failed to fetch user info: ' + response.message);
    } catch (error) {
        // Не меняем статус wallet.status тут, так как эта функция вызывается периодически для обновления информации
        wallet.lastError = `User info error: ${error.message}`;
        throw error;
    }
}

async function performSignIn(wallet, token) {
    try {
        wallet.status = 'signing in';
        const response = await apiRequest(
            `${API_BASE_URL}/task/signIn?status=true`,
            'GET',
            null,
            token,
            wallet.proxy,
            0,
            wallet
        );
        
        if (response.code === 200) {
            logMessage('Sign-in successful! Started farming.', 'success', wallet.address);
            wallet.status = 'farming';
            return true;
        }
        
        logMessage('Sign-in failed: ' + response.message, 'error', wallet.address);
        wallet.status = 'error';
        wallet.lastError = `Sign-in failed: ${response.message}`;
        return false;
    } catch (error) {
        wallet.status = 'error';
        wallet.lastError = `Sign-in error: ${error.message}`;
        logMessage(`Sign-in error: ${error.message}`, 'error', wallet.address);
        return false;
    }
}

async function claimReward(wallet, token) {
    try {
        wallet.status = 'claiming reward';
        logMessage('Initiating reward claim process...', 'info', wallet.address);

        logMessage('Preparing on-chain transaction...', 'info', wallet.address);

        // Создаем провайдера с повторными попытками
        const provider = new ethers.providers.JsonRpcProvider('https://rpc-mainnet.taker.xyz', {
            chainId: 1125,
            name: 'Taker',
            nativeCurrency: { name: 'Taker', symbol: 'TAKER', decimals: 18 }
        });

        const ethersWallet = new ethers.Wallet(wallet.privateKey, provider);

        const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, ethersWallet);

        // Получаем текущую цену на газ для более надежной транзакции
        let gasPrice;
        try {
            gasPrice = await provider.getGasPrice();
            // Увеличим немного для уверенности
            gasPrice = gasPrice.mul(ethers.BigNumber.from(12)).div(ethers.BigNumber.from(10)); // 1.2x
        } catch (error) {
            logMessage(`Failed to get gas price, using default: ${error.message}`, 'warning', wallet.address);
            gasPrice = ethers.utils.parseUnits('0.11', 'gwei');
        }

        const gasLimit = 200000; // Увеличенный газ лимит для надежности
        const maxPriorityFeePerGas = ethers.utils.parseUnits('0.11', 'gwei');
        const maxFeePerGas = gasPrice.add(maxPriorityFeePerGas);

        logMessage(`Gas settings: maxFeePerGas=${ethers.utils.formatUnits(maxFeePerGas, 'gwei')} gwei, maxPriorityFeePerGas=${ethers.utils.formatUnits(maxPriorityFeePerGas, 'gwei')} gwei, gasLimit=${gasLimit}`, 'info', wallet.address);

        // Проверяем баланс перед отправкой транзакции
        const balance = await provider.getBalance(wallet.address);
        const estimatedGasCost = maxFeePerGas.mul(gasLimit);
        
        if (balance.lt(estimatedGasCost)) {
            throw new Error(`Insufficient balance for gas. Have: ${ethers.utils.formatEther(balance)} TAKER, Need: ${ethers.utils.formatEther(estimatedGasCost)} TAKER`);
        }

        // Отправка транзакции с повторными попытками
        let tx;
        let retries = 0;
        
        while (retries <= MAX_RETRIES) {
            try {
                logMessage(`Sending transaction to call active() (attempt ${retries + 1})...`, 'info', wallet.address);
                tx = await contract.active({
                    gasLimit,
                    maxPriorityFeePerGas,
                    maxFeePerGas,
                    type: 2 
                });
                logMessage(`Transaction sent: ${tx.hash}`, 'info', wallet.address);
                break;
            } catch (error) {
                logMessage(`Transaction error: ${error.message}`, 'error', wallet.address);
                if (retries >= MAX_RETRIES) {
                    throw new Error(`Failed to send transaction after ${MAX_RETRIES} attempts: ${error.message}`);
                }
                retries++;
                await sleep(RETRY_DELAY * retries);
            }
        }

        // Ожидание подтверждения транзакции с дополнительной обработкой ошибок
        let receipt;
        retries = 0;
        
        while (retries <= MAX_RETRIES * 2) { // Больше попыток для ожидания подтверждения
            try {
                logMessage(`Waiting for transaction confirmation...`, 'info', wallet.address);
                receipt = await tx.wait();
                logMessage(`Transaction confirmed: ${receipt.transactionHash} | Gas used: ${receipt.gasUsed}`, 'success', wallet.address);
                break;
            } catch (error) {
                // Проверка статуса транзакции напрямую
                try {
                    const txStatus = await provider.getTransactionReceipt(tx.hash);
                    if (txStatus) {
                        if (txStatus.status === 1) {
                            logMessage(`Transaction successfully confirmed: ${tx.hash}`, 'success', wallet.address);
                            receipt = txStatus;
                            break;
                        } else {
                            throw new Error(`Transaction failed with status: ${txStatus.status}`);
                        }
                    }
                } catch (statusError) {
                    logMessage(`Error checking tx status: ${statusError.message}`, 'warning', wallet.address);
                }
                
                logMessage(`Waiting for confirmation error: ${error.message}`, 'warning', wallet.address);
                if (retries >= MAX_RETRIES * 2) {
                    // Если все попытки исчерпаны, считаем, что транзакция может быть в сети, продолжаем
                    logMessage(`Could not confirm transaction status. Continuing with next steps.`, 'warning', wallet.address);
                    break;
                }
                retries++;
                await sleep(RETRY_DELAY * retries);
            }
        }

        logMessage('Calling signIn API with status=false...', 'info', wallet.address);
        let signInSuccess = false;
        retries = 0;
        
        while (retries <= MAX_RETRIES && !signInSuccess) {
            try {
                const signInResponse = await apiRequest(
                    `${API_BASE_URL}/task/signIn?status=false`,
                    'GET',
                    null,
                    token,
                    wallet.proxy,
                    0,
                    wallet
                );

                if (signInResponse.code === 200) {
                    logMessage('Sign-in API (status=false) successful.', 'success', wallet.address);
                    signInSuccess = true;
                } else {
                    logMessage(`Sign-in API (status=false) failed: Code ${signInResponse.code} - ${signInResponse.message || 'Unknown error'}`, 'warning', wallet.address);
                    if (retries >= MAX_RETRIES) {
                        break;
                    }
                    retries++;
                    await sleep(RETRY_DELAY * retries);
                }
            } catch (error) {
                logMessage(`Error calling signIn API: ${error.message}`, 'error', wallet.address);
                if (retries >= MAX_RETRIES) {
                    break;
                }
                retries++;
                await sleep(RETRY_DELAY * retries);
            }
        }

        if (receipt || signInSuccess) {
            logMessage('Reward claimed successfully!', 'success', wallet.address);
            return true;
        } else {
            logMessage('Reward claim process had issues but may have succeeded.', 'warning', wallet.address);
            return true; // Предполагаем, что процесс прошел успешно, даже если были проблемы
        }
    } catch (error) {
        wallet.status = 'error';
        wallet.lastError = `Claim error: ${error.message}`;
        logMessage(`Error in claim process: ${error.message}`, 'error', wallet.address);
        return false;
    }
}

async function completeAndRestartFarmingCycle(wallet, token) {
    try {
        wallet.status = 'completing cycle';
        const claimSuccess = await claimReward(wallet, token);

        if (claimSuccess) {
            logMessage('Starting new farming cycle...', 'info', wallet.address);
            const signInSuccess = await performSignIn(wallet, token);

            if (signInSuccess) {
                const updatedUserInfo = await getUserInfo(wallet, token);

                if (currentWalletIndex === wallets.indexOf(wallet)) {
                    await updateUserInfo(wallet, token);
                    await updateFarmingStatus(wallet, token);
                }

                if (updatedUserInfo.nextTimestamp && updatedUserInfo.nextTimestamp > Date.now()) {
                    if (wallet.countdownInterval) {
                        clearInterval(wallet.countdownInterval);
                    }
                    startCountdown(wallet, token, updatedUserInfo.nextTimestamp);
                    return true;
                }
            }
        }

        logMessage('Failed to complete farming cycle. Will retry later.', 'warning', wallet.address);
        // Планируем повторную попытку через некоторое время
        setTimeout(() => {
            if (tokens[wallet.address]) {
                completeAndRestartFarmingCycle(wallet, tokens[wallet.address])
                    .catch(error => logMessage(`Retry farming cycle error: ${error.message}`, 'error', wallet.address));
            }
        }, RETRY_DELAY * 5); // Ждем в 5 раз дольше стандартной задержки
        
        return false;
    } catch (error) {
        wallet.status = 'error';
        wallet.lastError = `Farming cycle error: ${error.message}`;
        logMessage('Error in farming cycle: ' + error.message, 'error', wallet.address);
        return false;
    }
}


function formatTimeRemaining(timestamp) {
    const now = Date.now();
    const timeLeft = timestamp - now;
    if (timeLeft <= 0) return '00:00:00';
    const hours = Math.floor(timeLeft / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

async function updateUserInfo(wallet, token) {
    try {
        if (!token) {
            userInfoBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{red-fg}Not authenticated{/red-fg}`
            );
            return;
        }
        
        const userInfo = await getUserInfo(wallet, token);
        
        userInfoBox.setContent(
            `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${userInfo.walletAddress}{/green-fg}\n` +
            `{yellow-fg}Taker Points:{/yellow-fg} {green-fg}${userInfo.takerPoints}{/green-fg}\n` +
            `{yellow-fg}Consecutive Sign-Ins:{/yellow-fg} {green-fg}${userInfo.consecutiveSignInCount}{/green-fg}\n` +
            `{yellow-fg}Reward Count:{/yellow-fg} {green-fg}${userInfo.rewardCount}{/green-fg}`
        );
    } catch (error) {
        logMessage('Error updating user info: ' + error.message, 'error', wallet.address);
        
        // Проверяем ошибки авторизации и пытаемся переавторизоваться
        if (error.message.includes('401') || error.message.includes('auth') || error.message.includes('token')) {
            logMessage('Authentication error detected. Will try to re-authenticate...', 'warning', wallet.address);
            
            // Планируем переаутентификацию
            setTimeout(async () => {
                try {
                    const nonce = await generateNonce(wallet);
                    const newToken = await login(wallet, nonce);
                    tokens[wallet.address] = newToken;
                    logMessage('Re-authentication successful', 'success', wallet.address);
                    
                    // Обновляем информацию с новым токеном
                    await updateUserInfo(wallet, newToken);
                } catch (authError) {
                    logMessage('Re-authentication failed: ' + authError.message, 'error', wallet.address);
                }
            }, 2000);
        }
        
        // В любом случае показываем ошибку в интерфейсе
        userInfoBox.setContent(
            `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
            `{red-fg}Failed to fetch user info: ${error.message.slice(0, 50)}${error.message.length > 50 ? '...' : ''}{/red-fg}`
        );
    }
    screen.render();
}

async function updateFarmingStatus(wallet, token) {
    try {
        const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
        
        if (!token) {
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{red-fg}Not authenticated{/red-fg}`
            );
            return;
        }
        
        const userInfo = await getUserInfo(wallet, token);

        // Добавляем информацию о последней ошибке, если она есть
        const errorInfo = wallet.lastError ? 
            `\n{yellow-fg}Last Error:{/yellow-fg} {red-fg}${wallet.lastError.slice(0, 50)}${wallet.lastError.length > 50 ? '...' : ''}{/red-fg}` : '';

        if (userInfo.nextTimestamp && userInfo.nextTimestamp <= Date.now()) {
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{yellow-fg}Farming Status:{/yellow-fg} {yellow-fg}COMPLETED{/yellow-fg}\n` +
                `{yellow-fg}Action:{/yellow-fg} {yellow-fg}Automatically claiming reward and restarting...{/yellow-fg}` +
                errorInfo
            );
            screen.render();

            await completeAndRestartFarmingCycle(wallet, token);
        } else if (userInfo.nextTimestamp && userInfo.nextTimestamp > Date.now()) {
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{yellow-fg}Farming Status:{/yellow-fg} {green-fg}ACTIVE{/green-fg}\n` +
                `{yellow-fg}Next Farming Time:{/yellow-fg} {green-fg}${new Date(userInfo.nextTimestamp).toLocaleString()}{/green-fg}\n` +
                `{yellow-fg}Time Remaining:{/yellow-fg} {green-fg}${formatTimeRemaining(userInfo.nextTimestamp)}{/green-fg}` +
                errorInfo
            );

            if (!wallet.countdownInterval) {
                startCountdown(wallet, token, userInfo.nextTimestamp);
            }
        } else {
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{yellow-fg}Farming Status:{/yellow-fg} {red-fg}INACTIVE{/red-fg}\n` +
                `{yellow-fg}Action:{/yellow-fg} {yellow-fg}Starting farming...{/yellow-fg}` +
                errorInfo
            );
            screen.render();

            const signInSuccess = await performSignIn(wallet, token);
            if (signInSuccess) {
                const updatedUserInfo = await getUserInfo(wallet, token);
                farmingStatusBox.setContent(
                    `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                    `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                    `{yellow-fg}Farming Status:{/yellow-fg} {green-fg}ACTIVE{/green-fg}\n` +
                    `{yellow-fg}Next Farming Time:{/yellow-fg} {green-fg}${new Date(updatedUserInfo.nextTimestamp).toLocaleString()}{/green-fg}\n` +
                    `{yellow-fg}Time Remaining:{/yellow-fg} {green-fg}${formatTimeRemaining(updatedUserInfo.nextTimestamp)}{/green-fg}` +
                    errorInfo
                );

                if (wallet.countdownInterval) {
                    clearInterval(wallet.countdownInterval);
                }
                startCountdown(wallet, token, updatedUserInfo.nextTimestamp);
            }
        }
    } catch (error) {
        const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
        logMessage('Error updating farming status: ' + error.message, 'error', wallet.address);
        
        // Обработка ошибок авторизации
        if (error.message.includes('401') || error.message.includes('auth') || error.message.includes('token')) {
            wallet.lastError = `Auth error: ${error.message}`;
            
            // Переаутентификация произойдет в updateUserInfo
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{yellow-fg}Farming Status:{/yellow-fg} {red-fg}AUTH ERROR{/red-fg}\n` +
                `{yellow-fg}Action:{/yellow-fg} {yellow-fg}Attempting re-authentication...{/yellow-fg}`
            );
        } else {
            wallet.lastError = `Farming status error: ${error.message}`;
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{red-fg}Failed to fetch farming status: ${error.message.slice(0, 50)}${error.message.length > 50 ? '...' : ''}{/red-fg}`
            );
        }
    }
    screen.render();
}

function startCountdown(wallet, token, nextTimestamp) {
    if (wallet.countdownInterval) {
        clearInterval(wallet.countdownInterval);
    }

    const updateCountdown = async () => {
        const now = Date.now();
        const timeLeft = nextTimestamp - now;

        if (timeLeft <= 0) {
            logMessage('Farming cycle complete!', 'success', wallet.address);
            clearInterval(wallet.countdownInterval);
            wallet.countdownInterval = null;

            if (currentWalletIndex === wallets.indexOf(wallet)) {
                const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
                farmingStatusBox.setContent(
                    `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                    `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                    `{yellow-fg}Farming Status:{/yellow-fg} {yellow-fg}COMPLETED{/yellow-fg}\n` +
                    `{yellow-fg}Action:{/yellow-fg} {yellow-fg}Automatically claiming reward and restarting...{/yellow-fg}`
                );
                screen.render();
            }

            // Добавляем задержку перед началом процесса получения награды
            await sleep(2000);
            await completeAndRestartFarmingCycle(wallet, token);
            return;
        }

        if (currentWalletIndex === wallets.indexOf(wallet)) {
            const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
            // Обновляем информацию о последней ошибке
            const errorInfo = wallet.lastError ? 
                `\n{yellow-fg}Last Error:{/yellow-fg} {red-fg}${wallet.lastError.slice(0, 50)}${wallet.lastError.length > 50 ? '...' : ''}{/red-fg}` : '';
                
            farmingStatusBox.setContent(
                `{yellow-fg}Wallet Address:{/yellow-fg} {green-fg}${wallet.address}{/green-fg}\n` +
                `{yellow-fg}Proxy:{/yellow-fg} {green-fg}${proxyDisplay}{/green-fg}\n` +
                `{yellow-fg}Farming Status:{/yellow-fg} {green-fg}ACTIVE{/green-fg}\n` +
                `{yellow-fg}Next Farming Time:{/yellow-fg} {green-fg}${new Date(nextTimestamp).toLocaleString()}{/green-fg}\n` +
                `{yellow-fg}Time Remaining:{/yellow-fg} {green-fg}${formatTimeRemaining(nextTimestamp)}{/green-fg}` +
                errorInfo
            );
            screen.render();
        }
    };

    updateCountdown();
    wallet.countdownInterval = setInterval(updateCountdown, 1000);
}

// Функция мониторинга состояния каждого кошелька
async function monitorWallets() {
    for (const wallet of wallets) {
        try {
            // Если последний запрос был более 10 минут назад и у кошелька есть статус ошибки,
            // можно попробовать перезапустить процесс для этого кошелька
            const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
            
            if (wallet.lastSuccessfulRequest < tenMinutesAgo && 
                (wallet.status === 'error' || !wallet.status || !tokens[wallet.address])) {
                
                logMessage(`Wallet ${wallet.address} seems inactive or in error state. Attempting recovery...`, 'warning', wallet.address);
                
                try {
                    // Попытка переаутентификации
                    const nonce = await generateNonce(wallet);
                    const token = await login(wallet, nonce);
                    tokens[wallet.address] = token;
                    logMessage('Recovery authentication successful', 'success', wallet.address);
                    
                    // Проверяем текущее состояние фарминга
                    const userInfo = await getUserInfo(wallet, token);
                    
                    if (userInfo.nextTimestamp && userInfo.nextTimestamp <= Date.now()) {
                        // Если фарминг завершен, запускаем процесс получения награды
                        logMessage('Detected completed farming. Claiming reward...', 'info', wallet.address);
                        await completeAndRestartFarmingCycle(wallet, token);
                    } else if (!userInfo.nextTimestamp) {
                        // Если фарминг не активен, запускаем его
                        logMessage('No active farming detected. Starting farming...', 'info', wallet.address);
                        await performSignIn(wallet, token);
                    } else {
                        // Если фарминг активен, запускаем обратный отсчет
                        logMessage(`Farming in progress. Next claim in: ${formatTimeRemaining(userInfo.nextTimestamp)}`, 'info', wallet.address);
                        startCountdown(wallet, token, userInfo.nextTimestamp);
                    }
                    
                    // Обновляем информацию в интерфейсе если это текущий кошелек
                    if (currentWalletIndex === wallets.indexOf(wallet)) {
                        await updateUserInfo(wallet, token);
                        await updateFarmingStatus(wallet, token);
                    }
                } catch (recoveryError) {
                    logMessage(`Recovery attempt failed: ${recoveryError.message}`, 'error', wallet.address);
                }
            }
        } catch (error) {
            logMessage(`Error monitoring wallet ${wallet.address}: ${error.message}`, 'error', wallet.address);
        }
    }
}

async function runBot() {
    logMessage(`Starting Taker Auto-Farming Bot for ${wallets.length} wallet(s)`, 'info');

    // Создаем директорию для логов, если её нет
    try {
        const logDir = './logs';
        if (!fs.existsSync(logDir)){
            fs.mkdirSync(logDir);
        }
    } catch (error) {
        logMessage(`Failed to create logs directory: ${error.message}`, 'warning');
    }

    // Аутентификация всех кошельков
    for (const wallet of wallets) {
        try {
            logMessage(`Using proxy: ${wallet.proxy || 'None'}`, 'info', wallet.address);
            const nonce = await generateNonce(wallet);
            logMessage('Nonce generated: ' + nonce, 'info', wallet.address);
            const token = await login(wallet, nonce);
            tokens[wallet.address] = token;
            logMessage('Login successful! Token received.', 'success', wallet.address);
        } catch (error) {
            logMessage('Login failed: ' + error.message, 'error', wallet.address);
            // В случае ошибки добавляем кошелек в список для повторной попытки позже
            wallet.status = 'error';
            wallet.lastError = `Initial login failed: ${error.message}`;
        }
    }

    if (Object.keys(tokens).length === 0) {
        logMessage('No wallets authenticated. Retrying in 30 seconds...', 'error');
        setTimeout(runBot, 30000);
        return;
    }

    // Обновляем интерфейс для первого кошелька
    const firstWallet = wallets[currentWalletIndex];
    await updateUserInfo(firstWallet, tokens[firstWallet.address]);
    await updateFarmingStatus(firstWallet, tokens[firstWallet.address]);

    // Запускаем процесс фарминга для всех кошельков
    for (const wallet of wallets) {
        const token = tokens[wallet.address];
        if (token) {
            try {
                const userInfo = await getUserInfo(wallet, token);

                if (userInfo.nextTimestamp && userInfo.nextTimestamp <= Date.now()) {
                    logMessage('Farming cycle already complete. Claiming and restarting...', 'info', wallet.address);
                    await completeAndRestartFarmingCycle(wallet, token);
                } else if (userInfo.nextTimestamp && userInfo.nextTimestamp > Date.now()) {
                    logMessage(`Farming in progress. Next claim in: ${formatTimeRemaining(userInfo.nextTimestamp)}`, 'info', wallet.address);
                    startCountdown(wallet, token, userInfo.nextTimestamp);
                } else {
                    logMessage('No active farming detected. Starting farming...', 'info', wallet.address);
                    const signInSuccess = await performSignIn(wallet, token);
                    if (signInSuccess) {
                        const updatedInfo = await getUserInfo(wallet, token);
                        if (updatedInfo.nextTimestamp) {
                            startCountdown(wallet, token, updatedInfo.nextTimestamp);
                        }
                    }
                }
            } catch (error) {
                logMessage('Error setting up farming: ' + error.message, 'error', wallet.address);
                wallet.status = 'error';
                wallet.lastError = `Setup error: ${error.message}`;
            }
        }
    }

    // Периодическая проверка состояния фарминга
    const farmingCheckInterval = setInterval(async () => {
        for (const wallet of wallets) {
            const token = tokens[wallet.address];
            if (token) {
                try {
                    const userInfo = await getUserInfo(wallet, token);

                    if (userInfo.nextTimestamp && userInfo.nextTimestamp <= Date.now() && !wallet.countdownInterval) {
                        logMessage('Detected completed farming cycle. Processing...', 'info', wallet.address);
                        await completeAndRestartFarmingCycle(wallet, token);
                    } else if (!userInfo.nextTimestamp) {
                        logMessage('No active farming detected. Starting farming...', 'info', wallet.address);
                        await performSignIn(wallet, token);
                    }
                } catch (error) {
                    logMessage('Error in farming check: ' + error.message, 'error', wallet.address);
                    wallet.lastError = `Farming check error: ${error.message}`;
                    
                    // Если это ошибка авторизации, попытаемся переаутентифицироваться
                    if (error.message.includes('401') || error.message.includes('auth') || error.message.includes('token')) {
                        try {
                            logMessage('Authentication error detected. Re-authenticating...', 'warning', wallet.address);
                            const nonce = await generateNonce(wallet);
                            const newToken = await login(wallet, nonce);
                            tokens[wallet.address] = newToken;
                            logMessage('Re-authentication successful', 'success', wallet.address);
                        } catch (authError) {
                            logMessage(`Re-authentication failed: ${authError.message}`, 'error', wallet.address);
                        }
                    }
                }
            }
        }
    }, 60000); // Проверка каждую минуту

    // Периодическое обновление интерфейса
    const refreshInterval = setInterval(async () => {
        const wallet = wallets[currentWalletIndex];
        const token = tokens[wallet.address];
        if (token) {
            await updateUserInfo(wallet, token);
            await updateFarmingStatus(wallet, token);
        }
    }, 30000); // Обновление каждые 30 секунд

    // Запуск мониторинга кошельков для восстановления при ошибках
    const monitorInterval = setInterval(monitorWallets, 5 * 60 * 1000); // Проверка каждые 5 минут

    // Обработка горячих клавиш
    screen.key(['q', 'C-c'], () => {
        clearInterval(refreshInterval);
        clearInterval(farmingCheckInterval);
        clearInterval(monitorInterval);
        wallets.forEach(wallet => {
            if (wallet.countdownInterval) clearInterval(wallet.countdownInterval);
        });
        logMessage('Shutting down bot...', 'warning');
        setTimeout(() => {
            process.exit(0);
        }, 1000);
    });

    screen.key('r', async () => {
        logMessage('Manually refreshing authentication tokens...', 'info');
        for (const wallet of wallets) {
            try {
                const nonce = await generateNonce(wallet);
                const token = await login(wallet, nonce);
                tokens[wallet.address] = token;
                logMessage('Token refreshed successfully!', 'success', wallet.address);
                if (currentWalletIndex === wallets.indexOf(wallet)) {
                    await updateUserInfo(wallet, token);
                    await updateFarmingStatus(wallet, token);
                }
            } catch (error) {
                logMessage('Token refresh failed: ' + error.message, 'error', wallet.address);
            }
        }
    });

    screen.key(['left', 'h'], () => {
        currentWalletIndex = (currentWalletIndex - 1 + wallets.length) % wallets.length;
        const wallet = wallets[currentWalletIndex];
        modeBox.setContent(`{center}CURRENT MODE: {green-fg}AUTO-FARMING{/green-fg} | Wallet ${currentWalletIndex + 1} of ${wallets.length}{/center}`);
        updateUserInfo(wallet, tokens[wallet.address]);
        updateFarmingStatus(wallet, tokens[wallet.address]);
    });

    screen.key(['right', 'l'], () => {
        currentWalletIndex = (currentWalletIndex + 1) % wallets.length;
        const wallet = wallets[currentWalletIndex];
        modeBox.setContent(`{center}CURRENT MODE: {green-fg}AUTO-FARMING{/green-fg} | Wallet ${currentWalletIndex + 1} of ${wallets.length}{/center}`);
        updateUserInfo(wallet, tokens[wallet.address]);
        updateFarmingStatus(wallet, tokens[wallet.address]);
    });

    // Добавляем клавишу для вывода статуса всех кошельков
    screen.key('s', () => {
        logMessage('==== WALLET STATUS SUMMARY ====', 'info');
        wallets.forEach((wallet, index) => {
            const token = tokens[wallet.address] ? 'Authenticated' : 'Not authenticated';
            const errorInfo = wallet.lastError ? `Last error: ${wallet.lastError}` : 'No errors';
            logMessage(`Wallet ${index + 1}: ${wallet.address} | Status: ${wallet.status || 'unknown'} | Token: ${token} | ${errorInfo}`, 'info');
        });
        logMessage('=============================', 'info');
    });

    screen.on('resize', () => {
        screen.render();
    });

    screen.render();
}

runBot();
